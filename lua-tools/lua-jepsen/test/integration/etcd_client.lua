-- Simple etcd client written in Lua.
-- Source: https://github.com/anibali/etcd.lua
-- TODO: replace ltn12 with luafun

local json = require('json')
local http = require('http')
local ltn12 = require('ltn12')

local M = {}
local etcd = {}

local function to_query(data)
    local entries = {}
    for k, v in pairs(data) do
        if v ~= nil then
            table.insert(entries, k .. '=' .. tostring(v))
        end
    end
    return table.concat(entries, '&')
end

function etcd:request(opts)
    local http_opts = {
        url = self.addr .. opts.path,
        headers = {}
    }
    local http_client = http.client.new(http_opts)

    if opts.method ~= nil then http_opts.method = opts.method end

    if opts.params ~= nil then
        if http_opts.method == 'GET' or http_opts.method == 'DELETE' then
            http_opts.url = http_opts.url .. '?' .. to_query(opts.params)
        else
        local data = to_query(opts.params)
        http_opts.source = ltn12.source.string(data)
        http_opts.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        http_opts.headers['Content-Length'] = #data
        end
    end

    local buffer = {}
    http_opts.sink = ltn12.sink.table(buffer)

    local res, status = http_client.request(http_opts)
    local response_text = table.concat(buffer)

    if res == nil then
        return nil, status
    elseif status ~= 200 then
        return json.decode(response_text), status
    else
        return json.decode(response_text), nil
    end
end

function etcd:keys_get(key, params)
    return self:request{
        path = '/v2/keys/' .. key,
        method = 'GET',
        params = params
    }
end

function etcd:keys_put(key, params)
    return self:request{
        path = '/v2/keys/' .. key,
        method = 'PUT',
        params = params
    }
end

function etcd:keys_delete(key, params)
    return self:request{
        path = '/v2/keys/' .. key,
        method = 'DELETE',
        params = params
    }
end

function etcd:keys_post(key, params)
    return self:request{
        path = '/v2/keys/' .. key,
        method = 'POST',
        params = params
    }
end

function etcd:stats_leader()
    return self:request{
        path = '/v2/stats/leader',
        method = 'GET'
    }
end

function etcd:stats_self()
    return self:request{
        path = '/v2/stats/self',
        method = 'GET'
    }
end

function M.new(addr)
    local self = {}
    self.addr = addr or 'http://127.0.0.1:2379'

    setmetatable(self, {__index = etcd})
    return self
end

return M
