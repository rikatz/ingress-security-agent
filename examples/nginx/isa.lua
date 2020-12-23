local cjson = require('cjson.safe')
local http = require('resty.http')

local _M = {}

function _M.check()
  ngx.req.read_body()
  body = ngx.encode_base64(ngx.req.get_body_data())
  local headers, err = ngx.req.get_headers()
  request = {
    method = ngx.req.get_method(),
    path = ngx.var.uri, 
    query = ngx.var.query_string,
    version = tostring(ngx.req.http_version()),
    clientip = ngx.var.remote_addr, -- TODO: This should be changed to real IP
    serverip = ngx.var.server_addr,
    serverport = ngx.var.server_port,
    headers = headers,
    body = body,
  }
  text = cjson.encode(request)
  

  local httpc = http.new()
  --httpc:set_timeout = 50 -- TODO: This is in ms and should be configurable
  local resp, err = httpc:request_uri("http://172.17.0.2:8000", { -- TODO: Make ISA address configurable
    method  = "POST",
    path = "/modsecurity",
    body = text,
  })
  

  if resp.status == 403 then
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end 
  ngx.eof()
end

return _M
