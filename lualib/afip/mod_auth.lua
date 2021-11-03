local ngx = ngx
local JSON = require("afip.JSON")

local mod_auth = {}
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

local function check_exp_time(exp_time, opts)
    local exp_time_number = tonumber(exp_time, 10)
    if not exp_time then
        return "exp_time: invalid number [" .. (exp_time or "nil") .. "]"
    end

    local slack = opts.INITIAL_SLACK_SECONDS
    if exp_time_number > (ngx.time() + slack) then
        return "sso token not yet valid: exp_time[" .. exp_time .. "] ngx.time() [" .. ngx.time() .. " opts.INITIAL_SLACK_SECONDS [" .. slack .. "]"
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

local function get_authserver_publickey_pem(dn, opts)
    local service_name = get_cn_from_dn(dn)
    if not service_name then
        return nil, "dn [" .. dn .. "] without cn"
    end

    local publickey_pem = auth_servers_cache[service_name]
    if publickey_pem then
        ngx.log(ngx.INFO, "got publickey_pem of [" .. service_name .. "] from cache")
        return publickey_pem
    end

    local content, err = readAll(opts.CRYPTO_CONFIG_DIR .. service_name .. ".publickey.pem")
    if err then
        return nil, service_name .. ".publickey.pem not found"
    end
    auth_servers_cache[service_name] = content
    ngx.log(ngx.INFO, "put publickey_pem of [" .. service_name .. "] into cache")
    ngx.log(ngx.INFO, "publickey_pem of [" .. service_name .. "]: [" .. content .. "]")
    return content
end

local function get_afip_token_sing(opts)
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()

    if err then
        return nil, nil, ngx.HTTP_INTERNAL_SERVER_ERROR, err
    end

    if not args then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "no post args"
    end

    local token = args["token"]
    local sign = args["sign"]

    if not token then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "empty token"
    end

    if not sign then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "empty sign"
    end

    local sso_xml
    sso_xml, err = decode(token)
    if err then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "invalid token: " .. err
    end
    if not sso_xml:find("^<") then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "invalid xml token: does not start with <"
    end

    local xml2lua = require("xml2lua")
    -- https://github.com/manoelcampos/xml2lua/issues/29
    local handler = require("xmlhandler.tree"):new()
    local parser = xml2lua.parser(handler)
    parser:parse(sso_xml)

    local sso = handler.root.sso
    if not sso then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "invalid sso.xml"
    end

    if not sso.id then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "invalid sso.id"
    end

    if not sso.id._attr then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "empty sso.id"
    end

    local sso_payload = {}
    if not sso.id._attr.src then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "empty sso.id.src"
    end
    sso_payload.src = sso.id._attr.src

    local authserver_publickey_pem
    authserver_publickey_pem, err = get_authserver_publickey_pem(sso_payload.src, opts)
    if err then
        return nil, nil, ngx.HTTP_BAD_REQUEST, err
    end
    if not authserver_publickey_pem then
        return nil, nil, ngx.HTTP_INTERNAL_SERVER_ERROR, "not err and not authserver_publickey_pem !!!"
    end

    if not sso.id._attr.dst then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "empty sso.id.dst"
    end
    sso_payload.dst = sso.id._attr.dst

    if not sso.id._attr.exp_time then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "empty sso.id.exp_time"
    end
    sso_payload.exp_time = sso.id._attr.exp_time

    err = check_exp_time(sso_payload.exp_time, opts)
    if err then
        return nil, nil, ngx.HTTP_BAD_REQUEST, err
    end

    if not sso.operation then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "invalid sso.operation"
    end

    if not sso.operation.login then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "invalid sso.operation.login"
    end
    local login = sso.operation.login

    if not login._attr then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "sso.operation.login without attributes"
    end

    if not login._attr.service then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "invalid sso.operation.login.service"
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
        return nil, nil, ngx.HTTP_BAD_REQUEST, "sso.operation.login without relations and groups"
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

    return sso_payload, sign, nil, nil
end

function mod_auth.authenticate()
    local opts = {}
    opts.INITIAL_SLACK_SECONDS   = os.getenv("INITIAL_SLACK_SECONDS")   or 120
    opts.CRYPTO_CONFIG_DIR       = os.getenv("CRYPTO_CONFIG_DIR")       or "/secrets"
    opts.MY_PRIVATE_KEY_PEM_PATH = os.getenv("MY_PRIVATE_KEY_PEM_PATH") or "/secrets/myprivate.key"
    opts.MY_PUBLIC_KEY_PEM_PATH  = os.getenv("MY_PUBLIC_KEY_PEM_PATH")  or "/secrets/mypublic.key"

    ngx.log(ngx.INFO, "about executing afip.mod_auth.authenticate...")

    ngx.log(ngx.INFO, "with options [" .. JSON:encode(opts) .. "]")

    local sso, sign, status, err = get_afip_token_sing(opts)
    if err then
        ngx.status = status
        ngx.say(err)
        ngx.exit(ngx.status)
        return
    end

    ngx.say("sso [" , JSON:encode(sso), "]")
    ngx.say("sign [" , sign , "]")
    ngx.say("OK")
end

return mod_auth
