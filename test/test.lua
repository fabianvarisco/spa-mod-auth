-- https://leafo.net/guides/customizing-the-luarocks-tree.html
-- luarocks install lua-resty-openssl --local
-- sudo apt-get install luajit

print(package.path)

package.path = package.path .. ";./lualib/?.lua;" .. os.getenv("HOME") .."/.luarocks/share/lua/5.3/?.lua"

-- https://stackoverflow.com/questions/12676662/mocking-out-a-lua-module-using-package-preload

package.loaded.ngx = {
    null = nil,
    log = function(level, xx) print( tostring(level) .. " - " .. xx ) end
}

ngx = require("ngx")

--[[
local version=require "resty.openssl.version"

print("VERSION:")

local version_table = {
  "VERSION",
  "CFLAGS",
  "BUILT_ON",
  "PLATFORM",
  "DIR",
  "ENGINES_DIR",
  "VERSION_STRING",
  "FULL_VERSION_STRING",
  "MODULES_DIR",
  "CPU_INFO",
}

for _, k in ipairs(version_table) do
	print(string.format("%20s: %s", k, version.version(version[k])))
end

print(string.rep("-", 64))

-- local mod_auth = require("afip.mod_auth")

-- mod_auth.validate_token_sign("x", "x", {})
]]


-- https://github.com/daurnimator/lua-http
-- sudo apt-get install lua5.3-dev
-- luarocks install http --local

local http_request = require "http.request"
local headers, stream = assert(http_request.new_from_uri("http://localhome:8000"):go())
local body = assert(stream:get_body_as_string())
if headers:get ":status" ~= "200" then
    error(body)
end
print(body)
