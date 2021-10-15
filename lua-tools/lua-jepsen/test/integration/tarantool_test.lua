local fiber = require('fiber')
local fio = require('fio')
local fun = require('fun')
local net_box = require('net.box')
local log = require('log')

local jepsen = require('jepsen')
local cas_register_client = require('test.integration.tarantool_cas_register_client')

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

-- TODO: Parameterize with single instance and a cluster.
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

    local seed = os.time()
    math.randomseed(seed)
    log.info('Random seed: %s', seed)

    local r = cas_register_client.ops.r
    local w = cas_register_client.ops.w
    local cas = cas_register_client.ops.cas
    --[[
    local function generator()
        local n = 10000
        return fun.rands(0, 3):map(function(x)
                                       return (x == 0 and r()) or
                                              (x == 1 and w()) or
                                              (x == 2 and cas())
                                   end):take(n)
    end
    ]]
    local function generator()
        return fun.cycle(fun.iter({
            r(),
            w(),
            cas(),
        })):take(1000)
    end

    local test_options = {
        time_limit = 1000,
        threads = 5,
        nodes = {
            '127.0.0.1',
        },
    }
    local ok, err = jepsen.run_test({
        client = cas_register_client.new,
        generator = generator,
        checker = nil,
    }, test_options)
    t.assert_equals(ok, true)
    t.assert_equals(err, nil)
end
