local mod_auth = {}

local function decode(value)
    if value:find(' ') then
        value = value:gsub(' ', '+')
    elseif value:find('-') then
        value = value:gsub('-', '+')
    end

    local ret = ngx.decode_base64(value)
    if not ret then
        return nil, "Invalid encoding [" .. value .. "]"
    end

    return ret, nil
end

local function get_afip_token_sing(opts)
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()

    if err then
        return nil, nil, ngx.HTTP_INTERNAL_SERVER_ERROR, err
    end

    if not args then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "No post args"
    end

    local token = args["token"]
    local sign = args["sign"]

    if not token then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "Empty token"
    end

    if not sign then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "Empty sign"
    end

    local sso_xml, err = decode(token)

    if err then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "Invalid token: " .. err
    end

    local xml2lua = require("xml2lua")
    local handler = require("xmlhandler.tree")

    local parser = xml2lua.parser(handler)
    parser:parse(sso_xml)

    local sso = handler.root.sso

    if not sso then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "Invalid sso.xml"
    end

    local version = sso._attr.version
    local id = sso.id
    local operation = id.operation
    local login = operation.login

    if not version then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "Invalid sso.version"
    end

    if not id then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "Invalid sso.id"
    end

    if not operation then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "Invalid sso.id.operation"
    end

    if not login then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "Invalid sso.id.operation.login"
    end

    return sso_xml, sign, nil, nil
end

function mod_auth.authenticate(opts)
    ngx.log(ngx.INFO, "about executing afip.mod_auth.authenticate...")

    local sso, sign, status, err = get_afip_token_sing(opts)

    if err then
        ngx.status = status
        ngx.say(err)
        ngx.exit(ngx.status)
        return
    end

    ngx.say("sso.xml [" , sso , "]")
    ngx.say("sign [" , sign , "]")
    ngx.say("OK")
end

return mod_auth
