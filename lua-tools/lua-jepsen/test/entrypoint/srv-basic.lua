#!/usr/bin/env tarantool

local workdir = os.getenv('TARANTOOL_WORKDIR')
local listen = os.getenv('TARANTOOL_LISTEN')

box.cfg({
    work_dir = workdir,
    listen = listen,
    net_msg_max = 2 * 1024,
})

box.schema.user.grant('guest', 'create, read, write, execute, drop', 'universe')
box.schema.user.grant('guest', 'create', 'space')
box.schema.user.grant('guest', 'write', 'space', '_schema')
box.schema.user.grant('guest', 'write', 'space', '_space')

local space = box.schema.space.create('register_space')
space:format({
    { name='id', type='number' },
    { name='value', type='number' },
})
space:create_index('pk')

-- Function implements a CAS (Compare And Set) operation, which takes a key,
-- old value, and new value and sets the key to the new value if and only if
-- the old value matches what's currently there, and returns a status of
-- operation and old value in case of fail and a new value in case of success.
function cas(space_name, tuple_id, old_value, new_value) -- luacheck: ignore
    local space = box.space[space_name]
    box.begin()
    local tuple = space:get{tuple_id}
    if not tuple or tuple.value ~= old_value then
        box.commit()
        return old_value, false
    end
    local tuple = space:update(tuple_id, {{'=', 2, new_value}}, {timeout = 0.05})
    box.commit()
    assert(tuple ~= nil)

    return tuple.value, true
end
