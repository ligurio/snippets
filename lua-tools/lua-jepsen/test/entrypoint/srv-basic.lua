#!/usr/bin/env tarantool

local workdir = os.getenv('TARANTOOL_WORKDIR')
local listen = os.getenv('TARANTOOL_LISTEN')

box.cfg({
    work_dir = workdir,
    listen = listen,
    net_msg_max = 2 * 1024,
})

box.schema.user.grant('guest', 'create,read,write,execute,drop', 'universe')
box.schema.user.grant('guest', 'create', 'space')
box.schema.user.grant('guest', 'write', 'space', '_schema')
box.schema.user.grant('guest', 'write', 'space', '_space')

local space = box.schema.space.create('register_space')
space:format({
    { name='id', type='number' },
    { name='value', type='number' },
})
space:create_index('pk')
