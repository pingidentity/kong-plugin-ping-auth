local kong_response = kong.response

local NAME = "[ping-auth] "

local _M = {}

local nClock = 0
local is_circuit_closed = true
-- circuit Timer in seconds
local circuit_timer = 0

--[[
    Sends the provided Sideband request payload to the authorization URL
        config = the Kong provided plugin configuration
        parsed_url = the authorization URL parsed into it's component parts
        payload = the request payload; this will be used to send the sideband request
        return: the response status_code, headers, and body
]]
function _M.execute(config, parsed_url, payload)
      local response, err

      if (tonumber(os.difftime(os.time() - nClock)) > tonumber(circuit_timer) and is_circuit_closed == false) then
        is_circuit_closed = true
      end

      if (is_circuit_closed == true) then
        local httpc = _G.resty_httpc.new()
        local host = parsed_url.host
        local port = parsed_url.port

        httpc:set_timeout(config.connection_timeout_ms)

        -- send the request
        response, err = httpc:request_uri(config.service_url, {
            path = payload.path,
            query = payload.query,
            method = payload.method,
            version = payload.http_version,
            query = payload.query,
            headers = payload.headers,
            body = payload.body,
            ssl_verify = config.verify_service_certificate,
            keepalive_timeout = config.connection_keepAlive_ms
        })

        if response.status == 429 then
            nClock = os.time()
            is_circuit_closed = false
            circuit_timer = response.headers["Retry-After"]
            _M.is_failed_retry_request(circuit_timer)
         end

        if not response then
            ngx.log(ngx.ERR, string.format("%sFailed to send request to %s:%s: %s", NAME, host, port, err))
            return kong_response.exit(502)
        end

        if config.enable_debug_logging then
            ngx.log(ngx.DEBUG, string.format("%sReceived sideband response from policy provider: \n%s",
                    NAME, _M.response_tostring(response, payload.path)))
        end
        return tonumber(response.status), response.headers, response.body
      else
       is_circuit_closed = false
       _M.is_failed_retry_request(math.abs(os.difftime(os.time() - nClock)))
      end
end

--[[
    Parses a full URL string into a table containing its constituent components
        host_url = an unparsed string URL such as "https://example.com:443/test?foo=bar"
        return: a table containing the parsed URL; see documentation for luasocket/url.lua for more information
]]
function _M.parse_url(host_url)
    local scheme, host, port, path, query = unpack(_G.resty_httpc:parse_uri(host_url, false))

    if not port then
        if scheme == "http" then
            port = 80
        elseif scheme == "https" then
            port = 443
        end
    end

    if not path then
        path = "/"
    end

    local parsed_url = {
        scheme = scheme,
        host = host,
        port = port,
        path = path,
        query = query
    }

    return parsed_url
end

--[[
    Flattens a table of tables (the default returned by the sideband API "headers" field) into a single table.
    The table pairs are header names and arrays of header values.
        headers = a table of tables containing a single key/value pair
        return: a table containing pairs of header names and arrays of header values.

    Ex: { {"Content-Type"="application/json"}, {"Connection"="keep-alive"}, {"Multi-valued"="One"}, {"Multi-valued"="Two"} }
        => { "Content-Type"={"application/json"}, "Connection"={"keep-alive"}, "Multi-valued"={"One", "Two"} }
]]
function _M.flatten_headers(headers)
    local final_headers = {}
    for _, header in ipairs(headers) do
        for k, v in pairs(header) do
            k = k:lower()
            if final_headers[k] then
                final_headers[k][#final_headers[k] + 1] = v
            else
                final_headers[k] = { v }
            end
        end
    end
    return final_headers
end

--[[
    The opposite of flatten_headers, this function turns a Lua table of headers into a single table array containing
    tables that only contain a single header:value mapping. Multidimensional header values will return an error
    response to the client
        headers = a table of key:value pairs, where the value may be a table array for multi-value headers
        return = a table of tables containing a single header:value mapping each
]]
function _M.format_headers(headers)
    local final_headers = {}
    for key, val in pairs(headers) do
        key = key:lower()
        if type(val) ~= "table" then
            final_headers[#final_headers + 1] = { [key] = val }
        else
            for _, arr_val in ipairs(val) do
                if type(arr_val) == "table" then
                    ngx.log(ngx.ERR,
                            NAME .. "Unable to parse request headers: multidimensional header values not allowed.")
                    return kong.exit(400)
                else
                    final_headers[#final_headers + 1] = { [key] = arr_val }
                end
            end
        end
    end
    return final_headers
end

--[[
    Logs messages and determines if this request has a status code >=400
        status_code = the HTTP status code returned from the sideband API request
        body = the body of the sideband API request
        return: true if this status code is >=400
]]
function _M.is_failed_request(status_code, body)
    if status_code >= 400 and status_code < 500 then
        ngx.log(ngx.WARN, string.format("%sSideband request denied with status code %d: %s (%s)",
                NAME, status_code, body.message, body.id))
        if(status_code == 413) then
            _M.is_failed_request_custom_reponse(status_code, body)
        else
           return true
        end
    elseif status_code >= 500 then
        ngx.log(ngx.ERR, string.format("%sSideband request failed with status code %d: %s (%s)",
                NAME, status_code, body.message, body.id))
        return true
    end
    return false
end

--[[
 This function interrupts the current processing when the sideband response is 413 and produces a response.
]]
function _M.is_failed_request_custom_reponse(status_code, body)
      return kong.response.exit(status_code
        , body
        , {["Content-Type"] = "application/json"
          })
end

--[[
    return: 429 Too Many Requests Response with the time difference remaining in seconds
]]

function _M.is_failed_retry_request(time_remaining_seconds)
    return kong.response.exit(429
      , [[{"code": "LIMIT_EXCEEDED","message": "The request exceeded the allowed rate limit. Please try after 1 second."}]]
      , {["Content-Type"] = "application/json",
         ["Retry-After"] = tonumber(time_remaining_seconds)
        })

end

--[[
    Return a human readable string representation of a list of headers
        headers = a table of key:value header pairs
        return: a human readable string representation
]]
local function headers_tostring(headers)
    local header_string = ""
    local header_names = {}
    for key in pairs(headers) do
        header_names[#header_names + 1] = key
    end
    table.sort(header_names)
    for _, key in ipairs(header_names) do
        local val = headers[key]

        -- header values may be table arrays
        if type(val) == "table" then
            local val_string = "["
            for _, v in ipairs(val) do
                val_string = val_string .. v .. ", "
            end
            val_string = val_string:sub(1, #val_string - 2) .. "]"
            header_string = string.format("%s%s: %s\n", header_string, key, val_string)
        else
            header_string = string.format("%s%s: %s\n", header_string, key, val)
        end
    end

    return header_string
end

--[[
    Simple function to generate a string representation of a sideband request
        req = a request table
        return: a string containing a readable representation of the request
]]
function _M.request_tostring(req)
    local header_string = headers_tostring(req.headers)

    local path = req.path
    if req.query then
        path = path .. req.query
    end

    return string.format("%s %s HTTP/%s\n%s\n%s", req.method, path, req.http_version, header_string, req.body)
end

--[[
    Simple function to generate a string representation of a sideband response
        resp = a response table
        path = the path the response came from
        return: a string containing a readable representation of the response
]]
function _M.response_tostring(resp, path)
    local header_string = headers_tostring(resp.headers)
    return string.format("%s %s\n%s\n%s", resp.status, path, header_string, resp.body)
end

return _M
