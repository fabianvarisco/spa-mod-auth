local mod_auth = {}

-- main routine
local function xx(opts)
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()

    if err then
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say(err)
        ngx.exit(ngx.status)
    end

    if not args then
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say("No post args")
        ngx.exit(ngx.status)
    end

    local token = args["token"]
    local sign = args["sign"]

    if not token then
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say("Empty token")
        ngx.exit(ngx.status)
    end

    if not sign then
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say("Empty sign")
        ngx.exit(ngx.status)
    end

    ngx.say("token [", token, "]")

    local sso_xml = ngx.decode_base64(token)

    if not sso_xml then
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say("Invalid base64 token")
        ngx.exit(ngx.status)
    end

    return sso_xml, sign, err
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

    local sso_xml = ngx.decode_base64(token)

    if not sso_xml then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "Invalid encoded token"
    end

    return sso_xml, sign, nil, nil
end

function mod_auth.authenticate(opts)
    ngx.log(ngx.INFO, "about executing afip.mod_auth.authenticate...")

    local sso_xml, sign, status, err = get_afip_token_sing(opts)

    if err then
        ngx.status = status
        ngx.say(err)
        ngx.exit(ngx.status)
        return
    end

    ngx.say("sso.xml [" , sso_xml , "]")
    ngx.say("sign [" , sign , "]")
    ngx.say("OK")
end

return mod_auth
