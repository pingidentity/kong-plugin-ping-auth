local function split (input_string, sep)
   if sep == nil then
      sep = "//"
   end
   local t={}
   for str in string.gmatch(input_string, "([^"..sep.."]+)") do
      table.insert(t, str)
   end
   return t
end

local function parse_url(host_url)
    local scheme, host, version, path, query = table.unpack(split(host_url, "//"))

    scheme,_ = table.unpack(split(scheme, ":"))
    local port = 80
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

local function url_validator(config)
    local parsed_url = parse_url(string.lower(config.service_url))
    if parsed_url.scheme ~= "http" and parsed_url.scheme ~= "https" then
        return nil, "URL scheme must be either 'http' or 'https'"
    elseif parsed_url.host == nil or parsed_url.host == "" then
        return nil, "URL host cannot be blank"
    end
    return true
end

return {
    name = "ping-auth",
    fields = {
        { config = {
            type = "record",
            fields = {
                { service_url = { type = "string", required = true }, },
                { shared_secret = { type = "string", referenceable = true, required = true }, },
                { secret_header_name = { type = "string", required = true }, },
                { connection_timeout_ms = { type = "integer", required = false, default = 10000, gt = 0 }, },
                { connection_keepAlive_ms = { type = "integer", required = false, default = 60000, gt = 0 }, },
                { verify_service_certificate = { type = "boolean", required = false, default = true }, },
                { enable_debug_logging = { type = "boolean", required = false, default = false }, },
            },
            custom_validator = url_validator,
        }, },
    },
    entity_checks = {}
}
