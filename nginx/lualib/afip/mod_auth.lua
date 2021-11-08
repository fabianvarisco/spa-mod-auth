--[[
TODO:
1. avoid for ever session
2. more json claim specs
]]

local _M = {}

local ngx            = ngx
local JSON           = require("cjson")
local COOKIE         = require("resty.cookie")
local JWT            = require("resty.jwt")
local JWT_VALIDATORS = require("resty.jwt-validators")
local PKEY           = require("resty.openssl.pkey")
local JIT_UUID       = require("resty.jit-uuid")
local XML            = require("xml2lua")
local XML_HANDLER    = require("xmlhandler.tree")

JIT_UUID.seed() -- very important!

local OPTS = {}
OPTS.INITIAL_SLACK_SECONDS  = os.getenv("INITIAL_SLACK_SECONDS")   or 120
OPTS.CRYPTO_CONFIG_DIR      = os.getenv("CRYPTO_CONFIG_DIR")       or "/secrets"
OPTS.JWT_SECRET_TXT         = os.getenv("JWT_SECRET_TXT")          or "/secrets/jwtsecret.txt"
OPTS.JWT_EXP_SECONDS        = os.getenv("JWT_EXP_SECONDS")         or (60*60) -- an hour
OPTS.JWT_COOKIE_NAME        = os.getenv("JWT_COOKIE_NAME")         or "afip_jwt_token"
OPTS.JWT_COOKIE_PATH        = os.getenv("JWT_COOKIE_PATH")         or "/"
OPTS.JWT_COOKIE_DOMAIN      = os.getenv("JWT_COOKIE_DOMAIN")       or ngx.var.http_host
OPTS.JWT_TIMEIN_SECONDS     = os.getenv("JWT_TIMEIN_SECONDS")      or (60*5) -- five minutes
OPTS.HEADER_NAME            = os.getenv("HEADER_NAME")             or "x-afip-user"

ngx.log(ngx.INFO, "with options [" .. JSON.encode(OPTS) .. "]")

-- TODO: more specs
local JWT_CLAIM_SPEC = {
    jti = JWT_VALIDATORS.required(),
    iat = JWT_VALIDATORS.required(),
    exp = JWT_VALIDATORS.is_not_expired(),
    dst = JWT_VALIDATORS.required(),
    src = JWT_VALIDATORS.required(),
}

local JWT_SECRET_CONTENT = nil

local OK                    = ngx.OK
local BAD_REQUEST           = ngx.HTTP_BAD_REQUEST
local UNAUTHORIZED          = ngx.HTTP_UNAUTHORIZED
local INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR

local auth_servers_cache = {}

local function decode(value)
    for _, c in ipairs({' ', '-'}) do
        if value:find(c) then
            value = value:gsub(c, '+')
        end
    end

    local ret = ngx.decode_base64(value)
    if not ret then
        return nil, "not well formed base64 [" .. value .. "]"
    end

    return ret, nil
end

local function check_exp_time(exp_time)
    local exp_time_number = tonumber(exp_time, 10)
    if not exp_time then
        return "exp_time: invalid number [" .. (exp_time or "nil") .. "]"
    end

    local slack = OPTS.INITIAL_SLACK_SECONDS
    if exp_time_number > (ngx.time() + slack) then
        return "sso token not yet valid: exp_time[" .. exp_time .. "] ngx.time() [" .. ngx.time() .. " OPTS.INITIAL_SLACK_SECONDS [" .. slack .. "]"
    end
    return nil --OK!
end

local function readAll(file)
    local f = io.open(file, "rb")
    if not f then
        return nil, "file [" .. file .. "] not found"
    end
    local content = f:read("*all")
    f:close()
    return content, nil
end

local function split(input_str, sep)
    local parts = {}
    for part in string.gmatch(input_str, "([^" .. sep .. "]+)") do
        table.insert(parts, part)
    end
    return parts
end

local function all_trim(input_str)
    return input_str:match( "^%s*(.-)%s*$" )
end

local function get_cn_from_dn(dn)
    local parts = split(dn, ",")
    for _, part in ipairs(parts) do
        local parts2 = split(part, "=")
        if #parts2 == 2 and all_trim(parts2[1]) == "cn" then
            return all_trim(parts2[2])
        end
    end
    return nil
end

local function get_authserver_publickey(dn)
    local service_name = get_cn_from_dn(dn)
    if not service_name then
        return nil, "dn [" .. dn .. "] without cn"
    end

    -- ToDo: cache by name
    local pkey = auth_servers_cache[service_name]
    if pkey then
        -- gx.log(ngx.INFO, "got [" .. service_name .. "] publickey_pem from cache")
        return pkey
    end

    local content, err = readAll(OPTS.CRYPTO_CONFIG_DIR .. service_name .. ".publickey.pem")
    if err then
        return nil, service_name .. ".publickey.pem not found"
    end

    -- https://github.com/fffonion/lua-resty-openssl#pkeynew
    pkey, err = PKEY.new(content, {format = "PEM", type = "pu"})
    if err then
        return nil, "invalid " .. service_name .. ".publickey.pem: [" .. err .. "]"
    end

    auth_servers_cache[service_name] = pkey
    -- ngx.log(ngx.INFO, "put [" .. service_name .. "] publickey_pem into cache [" .. content .. "]")
    return pkey
end

local function get_afip_token_sing()
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()
    if err then
        ngx.log(ngx.ERR, debug.traceback(err))
        return nil, nil, INTERNAL_SERVER_ERROR, err
    end
    if not args then
        return nil, nil, BAD_REQUEST, "no post args"
    end

    local token = args["token"]
    if not token then
        return nil, nil, BAD_REQUEST, "empty token"
    end

    local sign = args["sign"]
    if not sign then
        return nil, nil, BAD_REQUEST, "empty sign"
    end

    return token, sign, nil, nil
end

local function verify_sso_xml_token(token, sign)
    local err
    if not token or type(token) ~= "string" then
        err = "param #1: token nil or not string"
        ngx.log(ngx.ERR, debug.traceback(err))
        return nil, INTERNAL_SERVER_ERROR, err
    end
    if not sign or type(sign) ~= "string" then
        err = "param #2: sign nil or not string"
        ngx.log(ngx.ERR, debug.traceback(err))
        return nil, INTERNAL_SERVER_ERROR, err
    end

    local sso_xml
    sso_xml, err = decode(token)
    if err then
        return nil, BAD_REQUEST, "invalid token: " .. err
    end

    if not sso_xml or type(sso_xml) ~= "string" then
        err = "sso_xml nil or not string"
        ngx.log(ngx.ERR, debug.traceback(err))
        return nil, INTERNAL_SERVER_ERROR, err
    end

    if not sso_xml:find("^<") then
        return nil, BAD_REQUEST, "invalid xml token: does not start with <"
    end

    -- https://github.com/manoelcampos/xml2lua/issues/29
    local handler = XML_HANDLER:new()
    XML.parser(handler):parse(sso_xml)

    local sso = handler.root.sso
    if not sso then
        return nil, BAD_REQUEST, "invalid sso.xml"
    end

    if not sso.id then
        return nil, BAD_REQUEST, "invalid sso.id"
    end

    if not sso.id._attr then
        return nil, BAD_REQUEST, "empty sso.id"
    end

    local sso_payload = {}
    if not sso.id._attr.src then
        return nil, BAD_REQUEST, "empty sso.id.src"
    end
    sso_payload.src = sso.id._attr.src

    local authserver_publickey
    authserver_publickey, err = get_authserver_publickey(sso_payload.src)
    if err then
        return nil, BAD_REQUEST, err
    end
    if not authserver_publickey then
        err = "not err and not publickey !!!"
        ngx.log(ngx.ERR, debug.traceback(err))
        return nil, INTERNAL_SERVER_ERROR, err
    end

    local sign2
    sign2, err = decode(sign)
    if err then
        return nil, BAD_REQUEST, "invalid sign: " .. err
    end

    local ok
    ok, err = authserver_publickey:verify(sign2, sso_xml)
    if err then
        ngx.log(ngx.ERR, debug.traceback(err))
        return nil, INTERNAL_SERVER_ERROR, err
    end
    if not ok then
        return nil, UNAUTHORIZED, "token signature mismatched: wrong-signature"
    end

    if not sso.id._attr.unique_id then
        return nil, BAD_REQUEST, "empty sso.id.unique_id"
    end
    sso_payload.unique_id = sso.id._attr.unique_id

    if not sso.id._attr.dst then
        return nil, BAD_REQUEST, "empty sso.id.dst"
    end
    sso_payload.dst = sso.id._attr.dst

    if not sso.id._attr.exp_time then
        return nil, BAD_REQUEST, "empty sso.id.exp_time"
    end
    sso_payload.sso_exp_time = sso.id._attr.exp_time

    err = check_exp_time(sso_payload.sso_exp_time)
    if err then
        return nil, UNAUTHORIZED, err
    end

    if not sso.operation then
        return nil, BAD_REQUEST, "invalid sso.operation"
    end

    if not sso.operation.login then
        return nil, BAD_REQUEST, "invalid sso.operation.login"
    end
    local login = sso.operation.login

    if not login._attr then
        return nil, BAD_REQUEST, "sso.operation.login without attributes"
    end

    if not login._attr.service then
        return nil, BAD_REQUEST, "invalid sso.operation.login.service"
    end
    sso_payload.service = login._attr.service
    sso_payload.uid     = login._attr.uid -- mandatory?

    sso_payload.groups = {}
    if login.groups and login.groups.group then
        for i, group in pairs(login.groups.group) do
            if group._attr and group._attr.name then
                sso_payload.groups[i] = group._attr.name
            end
        end
    end

    sso_payload.relations = {}
    if login.relations and login.relations.relation then
        for i, rel in pairs(login.relations.relation) do
            if rel._attr and rel._attr.key then
                sso_payload.relations[i] = rel._attr.key
            end
        end
    end

    if #sso_payload.relations == 0 and #sso_payload.groups == 0 then
        return nil, BAD_REQUEST, "sso.operation.login without relations and groups"
    end

    if login.info then
        sso_payload.info = {}
        if #login.info > 1 then
            for _, info in pairs(login.info) do
                if info._attr and info._attr.name and info._attr.value then
                    sso_payload.info[info._attr.name] = info._attr.value
                end
            end
        else
            local info = login.info
            if info._attr and info._attr.name and info._attr.value then
                sso_payload.info[info._attr.name] = info._attr.value
            end
        end
    end

	-- TODO: xml_auth_data.servicedata_from = NULL;
	-- TODO: xml_auth_data.servicedata_content = NULL;

    return sso_payload, nil, nil
end

local function load_JWT_SECRET_CONTENT()
    if not JWT_SECRET_CONTENT then
        local err
        JWT_SECRET_CONTENT, err = readAll(OPTS.JWT_SECRET_TXT)
        return err
    end
    return nil
end

local function make_jwt(payload)
    payload.iat = ngx.time()
    payload.exp = payload.iat + OPTS.JWT_EXP_SECONDS
    payload.jti = JIT_UUID()

    local assertion = {
      header = { typ = "JWT", alg = "HS512" },
      payload = payload
    }

    local err = load_JWT_SECRET_CONTENT()
    if err or not JWT_SECRET_CONTENT then
        return nil, nil, err or "not JWT_SECRET_CONTENT"
    end

    ngx.log(ngx.DEBUG, JSON.encode(assertion))

    local jwt_token = JWT:sign(JWT_SECRET_CONTENT, assertion)

    return jwt_token, assertion, nil
end

local function verify_jwt(jwt_token)
    local err = load_JWT_SECRET_CONTENT()
    if not JWT_SECRET_CONTENT or err then
        return nil, err or "not JWT_SECRET_CONTENT"
    end

    -- https://github.com/cdbattags/lua-resty-jwt#verify
    local jwt_object = JWT:verify(JWT_SECRET_CONTENT, jwt_token, JWT_CLAIM_SPEC)
    if not jwt_object or not jwt_object.verified or not jwt_object.valid then
        if jwt_object and jwt_object.reason then
            err = jwt_object.reason
        end
        return nil, err or "verify error but not reason"
    end

    return jwt_object, nil
end

local function set_cookie(jwt_token)
    -- https://github.com/cloudflare/lua-resty-cookie
    local cookie, err = COOKIE:new()
    if not cookie or err then
        return err or "not new cookie obejct"
    end

    -- TODO: test ngx.header['Set-Cookie'] = {'a=32; path=/', 'b=4; path=/'} to avoid require a module

    local ok
    ok, err = cookie:set({
        key = OPTS.JWT_COOKIE_NAME,
        value = jwt_token,
        path = OPTS.JWT_COOKIE_PATH,
        domain = OPTS.JWT_COOKIE_DOMAIN,
        secure = false,   -- TODO: set true
        httponly = false, -- TODO: set true
        samesite = "Strict"
    })
    if not ok or err then
        return err or "not cookie setting ok"
    end

    return nil
end

local function set_jwt_cookie(payload)
    local jwt_token, jwt_object, err = make_jwt(payload)
    if not jwt_token or not jwt_object or err then
        return nil, nil, err or "not jwt !!!"
    end

    err = set_cookie(jwt_token)
    if err then
        return nil, nil, err
    end

    return jwt_token, jwt_object, nil
end

local function exit_error_json(status, err)
    set_cookie(nil)
    ngx.status = status or INTERNAL_SERVER_ERROR
    ngx.say(JSON.encode({status = ngx.status, error = err or "nil"}))
    ngx.exit(ngx.status)
end

local function set_header(value)
    local name = OPTS.HEADER_NAME
    ngx.log(ngx.DEBUG, "ngx.req.set_header [" .. name .. "] with [" .. JSON.encode(value) .. "]")
    ngx.req.set_header(name, value)
    ngx.header[name] = value
end

function _M.login()
    print("...")

    local token, sign, status, err = get_afip_token_sing()
    if not token or not sign or err then
        exit_error_json(status, err or "not token or not sign!!!" )
        return
    end

    local payload
    payload, status, err = verify_sso_xml_token(token, sign)
    if not payload or err then
        exit_error_json(status, err or "not payload!!!")
        return
    end

    local jwt_token, jwt_object
    jwt_token, jwt_object, err = set_jwt_cookie(payload)
    if not jwt_token or not jwt_object or err then
        exit_error_json(INTERNAL_SERVER_ERROR, err or "not jwt !!!")
        return
    end

    set_header(payload)
end

local function get_jwt_from_cookie()
    -- https://github.com/cloudflare/lua-resty-cookie
    local cookie, err = COOKIE:new()
    if not cookie or err then
        return err or "not new cookie obejct"
    end

    local jwt_token
    jwt_token, err = cookie:get(OPTS.JWT_COOKIE_NAME)
    if not jwt_token or err then
        return err or "not cookie get ok"
    end
    return jwt_token, nil
end

local function is_time_to_renew(payload)
    local jti =  payload.jti or "nil"

    if jti == "nil" or not payload.iat or type(payload.iat) ~= "number" then
        ngx.log(ngx.WARN, "jti [" .. payload.jti .. "] nil or without iat: will not be renewed :(")
        return false -- mmm!!!
    end

    if payload.iat + OPTS.JWT_TIMEIN_SECONDS < ngx.time() then
       ngx.log(ngx.DEBUG, "jti [" .. jti .. "] is time to renew")
       return true
    end

    ngx.log(ngx.DEBUG, "jti [" .. jti .. "] will not be renewed yet")
    return false
end

function _M:secure()
    print("...")

    local jwt_token, err = get_jwt_from_cookie()
    if not jwt_token or err then
        exit_error_json(UNAUTHORIZED, err or "not jwt_token")
        return
    end

    local jwt_object
    jwt_object, err = verify_jwt(jwt_token)
    if not jwt_object or err then
        exit_error_json(UNAUTHORIZED, err or "not jwt_object")
        return
    end

    if is_time_to_renew(jwt_object.payload) then
        -- TODO: remove servicedata here !!!
        jwt_object, jwt_object, err = set_jwt_cookie(jwt_object.payload)
        if not jwt_object or err then
            exit_error_json(INTERNAL_SERVER_ERROR, err or "not renewed jwt!!!")
            return
        end
    end

    set_header(jwt_object.payload)
end

function _M:logout()
    print("...")
    set_cookie(nil)
    ngx.status = OK
    ngx.exit(ngx.status)
end

return _M
