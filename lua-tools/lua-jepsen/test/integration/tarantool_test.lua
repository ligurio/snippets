local fiber = require('fiber')
local fio = require('fio')
local net_box = require('net.box')
local log = require('log')

local jepsen = require('jepsen')
--local gen = require('jepsen.gen')
local fun = require('fun') -- FIXME: Use our own generators.

local bank_client = require('test.integration.tarantool_bank_client')
local cas_register_client = require('test.integration.tarantool_cas_register_client')

local t = require('luatest')
local g = t.group()

local Process = t.Process
local Server = t.Server

local seed = os.time()
math.randomseed(seed)
log.info('Random seed: %s', seed)

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
            timeout = 0.5,
        },
        function()
            t.assert(Process.is_pid_alive(pid))
        end
    )
    fiber.sleep(0.1) -- FIXME?
    local conn = net_box.connect('127.0.0.1:3301')
    t.assert_equals(conn:wait_connected(2), true)
    t.assert_equals(conn:ping(), true)
end

g.after_all = function()
    if server.process then
        server:stop()
    end
    fio.rmtree(datadir)
end

g.test_bank = function()
    t.skip('Unsupported')

    local read = bank_client.ops.read
    local transfer = bank_client.ops.transfer
    local function generator()
        return fun.cycle(fun.iter({
            read(),
            transfer(),
        })):take(5000)
    end

    local test_options = {
        threads = 10,
        nodes = {
            '127.0.0.1:3301',
        },
    }
    local ok, err = jepsen.run_test({
        client = bank_client.new,
        generator = generator,
    }, test_options)
    t.assert_equals(ok, true)
    t.assert_equals(err, nil)
end

g.test_cas_register = function()
    local r = cas_register_client.ops.r
    local w = cas_register_client.ops.w
    local cas = cas_register_client.ops.cas
    local function generator()
        return fun.cycle(fun.iter({
            r(),
            w(),
            cas(),
        })):take(10000)
    end

    local test_options = {
        threads = 5,
        nodes = {
            '127.0.0.1:3301',
        },
    }
    require('jit.p').start('f', 'profile.txt') -- Performance.
    local ok, err = jepsen.run_test({
        client = cas_register_client.new,
        generator = generator,
    }, test_options)
    require('jit.p').stop() -- Performance.

    t.assert_equals(ok, true)
    t.assert_equals(err, nil)
end
