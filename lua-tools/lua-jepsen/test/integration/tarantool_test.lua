local net_box = require('net.box')
local fiber = require('fiber')
local fio = require('fio')
local jepsen = require('jepsen')
local register_workload = require('test.integration.tarantool_register_workload')

local t = require('luatest')
local g = t.group()

local Process = t.Process
local Server = t.Server

local root = fio.dirname(fio.dirname(fio.abspath(package.search('test.helper'))))
local datadir = fio.tempdir()

local server = Server:new({
    command = fio.pathjoin(root, 'test', 'entrypoint', 'srv-basic.lua'),
    workdir = fio.pathjoin(datadir),
    net_box_port = 3301,
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
        end
    )
end

g.after_all = function()
    if server.process then
        server:stop()
    end
    fio.rmtree(datadir)
end

g.test_register = function()
    fiber.sleep(0.1)
    local conn = net_box.connect('127.0.0.1:3301')
    t.assert_equals(conn:wait_connected(0.5), true)
    t.assert_equals(conn:ping(), true)

    local test_settings = {
        time_limit = 1,
        threads = 1,
        nodes = {
            '127.0.0.1'
        },
    }
    local _, err = jepsen.run_test(register_workload, test_settings)
    t.assert_equals(err, nil)
end
