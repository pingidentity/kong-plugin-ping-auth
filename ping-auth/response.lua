local kong_request = kong.request
local kong_response = kong.response
local kong_service_response = kong.service.response
local ngx_req = ngx.req

local NAME = "[ping-auth] "
local SIDEBAND_RESPONSE_ENDPOINT = "sideband/response"

local enable_debug_logging

-- Response headers to be kept even if the policy provider doesn't include them in the response
local ALLOWED_HEADERS = {
    ["content-length"] = true,
    ["date"] = true,
    ["connection"] = true,
    ["vary"] = true
}

local _M = {}

--[[
    Send a sideband POST request to <authorization url>/sideband/response and handle the response accordingly
        config = the Kong provided plugin configuration
        original_request = the request sent to the API
        state = the state field returned from the policy provider in the response from /sideband/request (may be nil)
        return: nil
]]
function _M.execute(config, original_request, state)
    local parsed_url = _G.network_handler.parse_url(config.service_url)
    local request = _M.compose_payload(config, original_request, state, parsed_url)

    enable_debug_logging = config.enable_debug_logging
    if enable_debug_logging then
        ngx.log(ngx.DEBUG, string.format("%sSending sideband response request to policy provider: \n%s",
                NAME, _G.network_handler.request_tostring(request)))
    end

    local status_code, _, body = _G.network_handler.execute(config, parsed_url, request)
    return _M.handle_response(status_code, body)
end

--[[
    Build the sideband request
        config = the Kong provided plugin configuration
        original_request = the request sent to the API
        state = the state field returned from the policy provider in the response from /sideband/request (may be nil)
        parsed_url = the authorization URL parsed into it's component parts
        return: a table containing all the parameters needed to send an HTTP request
]]
function _M.compose_payload(config, original_request, state, parsed_url)
    -- populate request data in the format expected by the sideband API
    local payload_body = {}
    payload_body.method = ngx_req.get_method()
    payload_body.url = kong_request.get_forwarded_scheme() .. "://" .. kong_request.get_forwarded_host() .. ":" ..
            kong_request.get_forwarded_port() .. kong_request.get_forwarded_path()
    payload_body.body = kong_service_response.get_raw_body()

    local response_code = kong_response.get_status()
    payload_body.response_code = tostring(response_code)
    payload_body.response_status = _M.get_status_string(response_code)
    payload_body.headers = _G.network_handler.format_headers(kong_response.get_headers())

    local uri_args_string = kong.request.get_raw_query()
    local uri_args = ngx.decode_args(uri_args_string, 100)

    local raw_query = ngx.encode_args(uri_args)
    if raw_query ~= '' then
        payload_body.url = payload_body.url .. "?" .. raw_query
    end

    local http_version = tostring(ngx_req.http_version())
    if http_version:find("^2") then
        ngx.log(ngx.ERR, string.format("%sHTTP/2 not supported by ping-auth (attempted to use version \"%s\")", NAME, http_version))
        return kong_response.exit(500)
    end
    payload_body.http_version = http_version

    if state then
        payload_body.state = state
    else
        payload_body.request = original_request
    end

    local json_payload_body, err = _G.cjson.encode(payload_body)
    if not json_payload_body then
        ngx.log(ngx.ERR, string.format("%sUnable to parse JSON body. Error: %s", NAME, err))
        return kong_response.exit(500)
    end

    -- parse out the full authorization path, including the sideband request endpoint
    local path = parsed_url.path
    if path:sub(-1) ~= "/" then
        path = path .. "/"
    end
    path = path .. SIDEBAND_RESPONSE_ENDPOINT

    local host = parsed_url.host
    if parsed_url.port then
        host = host .. ":" .. parsed_url.port
    end

    -- combine full request
    local payload_headers = {
        ["Host"] = host,
        ["Connection"] = "Keep-Alive",
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "Kong/" .. _G.PLUGIN_VERSION,
        ["Content-Length"] = #json_payload_body,
        [config.secret_header_name] = config.shared_secret
    }

    local payload = {
        method = "POST",
        http_version = 1.1,
        path = path,
        query = parsed_url.query,
        headers = payload_headers,
        body = json_payload_body
    }

    return payload
end

--[[
    Handle the sideband response returned from Ping
        status_code = the HTTP status code returned from the sideband API request
        body = the body of the sideband API request
        return: nil, sends the response back to the client
]]
function _M.handle_response(status_code, body)
    local err
    body, err = _G.cjson.decode(body)
    if not body then
        ngx.log(ngx.ERR, string.format("%sUnable to parse JSON body returned from policy provider. Error: %s",
                NAME, err))
        return kong_response.exit(502)
    end

    -- handle failed requests
    if _G.network_handler.is_failed_request(status_code, body) then
        return kong_response.exit(502)
    end

    -- remove response headers not included in the response from the policy provider
    local flattened_headers = _G.network_handler.flatten_headers(body.headers)
    for k, _ in pairs(kong_response.get_headers()) do
        if not flattened_headers[k] and not ALLOWED_HEADERS[k] then
            if enable_debug_logging then
                ngx.log(ngx.DEBUG, string.format("%sRemoving header '%s' that wasn't included in the response " ..
                    "from the policy provider", NAME, k))
            end
            kong_response.clear_header(k)
        end
    end

    return kong_response.exit(tonumber(body.response_code), body.body, flattened_headers)
end

--[[
    Returns the status string for the most common status codes expected to be returned by the Sideband API.
        status_code = the HTTP status code returned from the sideband API request
        return: a status string corresponding to the supplied code
]]
function _M.get_status_string(status_code)
    if status_code == 200 then
        return "OK"
    elseif status_code == 400 then
        return "BAD REQUEST"
    elseif status_code == 401 then
        return "UNAUTHORIZED"
    elseif status_code == 404 then
        return "NOT FOUND"
    elseif status_code == 413 then
        return "PAYLOAD TOO LARGE"
    elseif status_code == 500 then
        return "INTERNAL SERVER ERROR"
    elseif status_code == 429 then
        return "TOO MANY REQUESTS"
    elseif status_code == 503 then
        return "SERVICE UNAVAILABLE"
    end
    return ""
end

return _M
