local mod_auth = {}

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

    local sso_xml, err = decode(token)
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

    if not sso.id._attr.dst then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "empty sso.id.dst"
    end
    sso_payload.dst = sso.id._attr.dst

    if not sso.id._attr.exp_time then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "empty sso.id.exp_time"
    end
    sso_payload.exp_time = sso.id._attr.exp_time

    if not sso.operation then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "invalid sso.operation"
    end

    if not sso.operation.login then
        return nil, nil, ngx.HTTP_BAD_REQUEST, "invalid sso.operation.login"
    end

    if sso.operation.login._attr and sso.operation.login._attr.uid then
        sso_payload.uid = sso.operation.login._attr.uid
    end
    local login = sso.operation.login

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

function mod_auth.authenticate(opts)
    ngx.log(ngx.INFO, "about executing afip.mod_auth.authenticate...")

    local sso, sign, status, err = get_afip_token_sing(opts)
    if err then
        ngx.status = status
        ngx.say(err)
        ngx.exit(ngx.status)
        return
    end

    local JSON = require("afip.JSON")
    ngx.say("sso [" , JSON:encode(sso), "]")
    ngx.say("sign [" , sign , "]")
    ngx.say("OK")
end

return mod_auth
