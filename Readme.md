# `ping-auth` Kong Gateway Plugin

## Table of Contents
* [Overview](#overview)
* [File Structure](#file-structure)
* [Installation](#installation)
* [Configuration](#configuration)
* [Usage](#usage)
  * [Mutual TLS (mTLS)](#mutual-tls-mtls)
  * [Transfer-Encoding](#transfer-encoding)
* [Useful links](#useful-links)

## Overview

[Kong Gateway](https://docs.konghq.com/gateway/) is a [Lua](https://www.lua.org/) module built on 
[OpenResty](https://openresty.org/en/), which is a Lua adaptation of NGINX. Kong allows granular control of the 
entire request/response cycle by allowing for the use of third-party Lua modules, which it refers to as 
"plugins". The `ping-auth` plugin was created to allow Kong deployments to utilize Ping products as policy 
providers via the Sideband API protocol.

The Kong Plugin Development Kit (PDK) allows plugins to interface with Kong at various stages in the 
request/response cycle by providing a set of callback functions that plugins can tie into. As an authentication 
plugin, `ping-auth` primarily acts in the `access` phase (after Kong recieves a request but before forwarding 
it to the API) and the `response` phase (after a response is received from the API but before sending it to 
the client). During these phases, `ping-auth` makes a sideband request to the Ping service, then receives 
and properly applies the response.

### File Structure

* `schema.lua` - Defines plugin configuration fields and performs basic validation
* `handler.lua` - Entry point for Kong; provides callbacks to custom lifecycle functions
* `access.lua`/`response.lua` - Handling for specific lifecycle functions
* `network_handler.lua` - Utility class for network handling and helper functions

## Installation

This plugin can be installed by following the LuaRocks or Manual Installation steps in 
[Kong's Installation guide](https://docs.konghq.com/gateway-oss/2.5.x/plugin-development/distribution/#installing-the-plugin).

To install via LuaRocks, run the following command:
```
luarocks install kong-plugin-ping-auth
```
After installation, the plugin can be loaded into Kong by editing the following property in `kong.conf`:
```
plugins = bundled,ping-auth
```
Loading can be confirmed by looking for the debug-level message `Loading plugin: ping-auth` in Kong's `error.log`.

Some general tips for manual installation on RHEL8:
* The Kong configuration file is located at `/etc/kong/kong.conf` and the rest of the files (like the logs) are 
located at `/usr/local/kong/`
* Instead of modifying `lua_package_path` in the conf file, it may be easier to simply put the plugin directory 
into `/usr/local/share/lua/5.1/kong/plugins/` with all the default plugins. This property must still be modified in 
the conf file: `plugins = bundled,ping-auth`

## Configuration

One installed, the `ping-auth` plugin can be enabled and configured either via Kong's admin UI the API. 
It can be applied granularly to a specific Route or Service, 
or globally to apply sideband authentication to all Routes/Services.

Here's a description of all the currently provided configuration options:
* `service_url` (*required*) - The full URL of the Ping policy provider; this should not contain `/sideband...` in the path
* `shared_secret` (*required*) - The shared secret value to authenticate this plugin to the policy provider
* `secret_header_name` (*required*) - The header name in which the shared secret should be provided
* `connection_timeout_ms` (*optional*, default `10000`) - The duration to wait before timing out a connection
* `connection_keepAlive_ms` (*optional*, default `60000`) - The duration to keep a connection alive for reuse
* `verify_service_certificate` (*optional*, default `true`) - Controls whether the service certificate should be 
verified; intended for testing purposes
* `enable_debug_logging` (*optional*, default `false`) - Controls if requests/responses should be logged at the DEBUG level
  * NOTE: `log_level = debug` must be set in `kong.conf` in order for the log messages to appear in the `error.log`
  

## Usage

### Mutual TLS (mTLS)

This plugin does support client certificate authentication via mTLS, however this features requires using
the `mtls-auth` plugin (only available in the Enterprise edition of Kong) in conjunction with `ping-auth`.
Documentation for `mtls-auth` can be found [here](https://docs.konghq.com/hub/kong-inc/mtls-auth/). When
configured, this plugin will go through the mTLS dance in order to retrieve the client certificate, which
then allows `ping-auth` to provide the certificate in the `client_certificate` field of the sideband requests.

### Transfer-Encoding

Currently, due to an outstanding defect in Kong, `ping-auth` is unable to support the `Transfer-Encoding`
header regardless of the value. This defect is being tracked on [GitHub](https://github.com/Kong/kong/issues/8083).

## Useful links

* [Kong Plugin Development Guide](https://docs.konghq.com/gateway/2.6.x/plugin-development/)
* [Kong PDK Reference](https://docs.konghq.com/gateway/2.6.x/pdk/)
* [OpenResty Lua NGINX Reference](https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/)
* [Lua Syntax Cheatsheet](https://devhints.io/lua)
* [Lua Tutorial](https://www.youtube.com/watch?v=iMacxZQMPXs)
