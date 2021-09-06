-- список возможных тестов Jepsen
-- https://keplerproject.github.io/luasql/manual.html
-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/fiber/
-- https://gist.github.com/sergos/c2dae39bf1ac47519356de23601ea7f4
-- https://aphyr.com/posts/316-jepsen-etcd-and-consul
-- https://luafun.github.io/basic.html
-- https://github.com/tarantool/p2phub/blob/60a511ac80f376842ac4187bc4decc498b6abf59/src/lib/hashing.lua#L46-L65

local fiber = require('fiber')
local clock = require('clock')
local fun = require('fun')
local net_box = require('net.box')
local math = require('math')

math.randomseed(os.time())

local n_fibers = 50
local n_ops = 1000000
local op_channel = fiber.channel(n_ops)
local res_channel = fiber.channel(2 * n_ops)

box.cfg{
    listen = 3301,
    net_msg_max = 2 * 1024,
}

box.once('schema', function()
    box.schema.space.create('test')
    box.space.test:create_index('primary')
    box.schema.user.grant('guest', 'read, write, execute', 'universe')
end)

local function r()
    return { type = 'invoke', f = 'read', v = nil }
end

local function w()
    return { type = 'invoke', f = 'write', v = math.random(1, 10) }
end

local function cas()
    return {
        type = 'invoke',
        f = 'cas',
        v = {math.random(1, 10), math.random(1, 10)}
    }
end

local function cas_op(id, val1, val2, space)
    box.begin()
    local tuple = box.space[space]:get{id}
    if tuple then
        if tuple[2] == val1 then
            box.space[space]:update({id}, {{'=', 2, val2}})
        end
    end
    box.commit()
end

local function register_client(ch_in, ch_out)
    local conn = net_box.connect('127.0.0.1:3301')
    assert(conn:ping(), true)
    local ok
    while not ch_in:is_empty() do
        local op = ch_in:get()
        ch_out:put({ type = op.type, f = op.f, time = clock.time() })
        if op.f == 'write' then
            ok = pcall(conn.space.test:replace({1, op.v}))
        elseif op.f == 'read' then
            ok = pcall(conn.space.test:select(1))
        elseif op.f == 'cas' then
            ok = cas_op(1, op.v[1], op.v[2], 'test')
        end
        ch_out:put({ type = ok, f = op.f, time = clock.time() })
        fiber.yield()
    end
    print('client close connection')
    conn:close()
end

local function process_results(ch)
    while not ch:has_writers() do
        local res = ch:get()
        local inspect = require('inspect')
        print(inspect.inspect(res, {newline=' ', indent=''}))
    end
end

local function generate_operations(gen)
    for _, operation in pairs(gen) do
        print('Generate new operation, current channel length', op_channel:count())
        op_channel:put(operation())
        fiber.yield()
    end
end

local function main()
    -- generate operations
    local gen = fun.rands(0, 3):map(function(x)
                                    return (x == 0 and r) or
                                        (x == 1 and w) or
                                        (x == 2 and cas) end):take(n_ops):totable()
    fiber.create(generate_operations, gen)

    -- start clients
    for n = 1, n_fibers do
        fiber.create(register_client, op_channel, res_channel)
        print('\bStart client', n)
        io.flush()
    end
    os.exit()

    -- start processing
    local f = fiber.create(process_results, res_channel)
    f:set_joinable(true)
    f:join()

    -- teardown
    if op_channel:is_empty() and not op_channel:has_readers() then
        op_channel:close()
    end
    if res_channel:is_empty() and not res_channel:has_writers() then
        res_channel:close()
    end
end

main()

os.exit(0)
