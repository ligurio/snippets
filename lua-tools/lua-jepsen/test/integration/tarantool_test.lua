local fio = require('fio')
local json = require('json')

local t = require('luatest')
local g = t.group()

local Process = t.Process
local Server = t.Server

local root = fio.dirname(fio.dirname(fio.abspath(package.search('test.helper'))))
local datadir = fio.pathjoin(root, 'tmp', 'db_test')

local server = Server:new({
    command = fio.pathjoin(root, 'test', 'entrypoint', 'srv-basic.lua'),
    workdir = fio.pathjoin(datadir, 'common'),
    net_box_port = 3133,
})

g.before_all = function()
    fio.rmtree(datadir)
    fio.mktree(server.workdir)
    server:start()
    local pid = server.process.pid
    t.helpers.retrying(
        {
            timeout = 0.5
        },
        function()
            t.assert(Process.is_pid_alive(pid))
        end)
end

g.after_all = function()
    if server.process then
        server:stop()
    end
    fio.rmtree(datadir)
end

g.test_register = function()
    t.assert_equals(1, 1)
end
