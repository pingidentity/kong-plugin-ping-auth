local access = require("kong.plugins.ping-auth.access")
local response = require("kong.plugins.ping-auth.response")
_G.cjson = require "cjson.safe"
_G.x509 = require "resty.openssl.x509"
_G.network_handler = require("kong.plugins.ping-auth.network_handler")
_G.resty_httpc = require "resty.http"

local kong_response = kong.response

local NAME = "[ping-auth] "

local PingHandler = {
  VERSION = "1.2.0",
  PRIORITY = 999
}

_G.PLUGIN_VERSION = PingHandler.VERSION;

-- These objects are used to pass request information between the "access" and "response" phases
PingHandler.request = {}
PingHandler.state = {}

--[[
    Tie into Kong's access phase to make the first sideband call. Basic error handling is done to ensure this phase
    rejects any requests if an unexpected error is encountered (fail-closed)
        config = the Kong provided plugin configuration
        return: nil
]]
function PingHandler:access(config)
    local ok
    ok, PingHandler.request, PingHandler.state = pcall(access.execute, config)

    if not ok then
        ngx.log(ngx.ERR, string.format("%sEncountered unexpected error: %s", NAME, PingHandler.request))
        return kong_response.exit(500)
    end
end

--[[
    Tie into Kong's response phase to make the second sideband call. Basic error handling is done to ensure this phase
    rejects any requests if an unexpected error is encountered (fail-closed)
        config = the Kong provided plugin configuration
        return: nil
]]
function PingHandler:response(config)
    local ok, err = pcall(response.execute, config, PingHandler.request, PingHandler.state)

    if not ok then
        ngx.log(ngx.ERR, string.format("%sEncountered unexpected error: %s", NAME, err))
        return kong_response.exit(500)
    end
end

return PingHandler
