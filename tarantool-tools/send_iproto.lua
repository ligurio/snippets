#!/usr/bin/env tarantool

local socket = require('socket')
local urilib = require('uri')
local fio = require('fio')
local os = require('os')

--os.execute('rm *.{snap.xlog}')
box.cfg({
    listen = 3301
})

local uri = urilib.parse(box.cfg.listen)
local sock = socket.tcp_connect(uri.host, uri.service)
sock:read(128)
local fh = fio.open(arg[1])
sock:write(fh:read())
fh:close()
sock:close()
os.exit()
