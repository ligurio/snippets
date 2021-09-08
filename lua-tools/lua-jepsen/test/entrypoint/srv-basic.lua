#!/usr/bin/env tarantool

local workdir = os.getenv('TARANTOOL_WORKDIR')
local listen = os.getenv('TARANTOOL_LISTEN')
box.cfg({
    work_dir = workdir,
    listen = listen,
    net_msg_max = 2 * 1024,
})

box.once('schema', function()
    box.schema.user.create('storage', {password = 'storage'})
    box.schema.user.grant('storage', 'replication') -- grant replication role
    box.schema.user.grant('storage', 'execute', 'universe')
    box.schema.user.grant('guest', 'read, write, execute', 'universe')
end)
