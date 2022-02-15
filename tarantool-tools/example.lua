buffer = require 'buffer'
msgpack = require 'msgpack'
ffi = require 'ffi'

buf = buffer.ibuf()

msgpack.encode('test', buf)
collectgarbage()       -- forces a garbage collection cycle

local a = 45
local b = 'aabbcc'

decimal = require('decimal')
collectgarbage()       -- forces a garbage collection cycle
a = decimal.new('1e37')
b = decimal.new('1e-38')
c = decimal.new('1')
d = decimal.new('0.1234567')
e = decimal.new('123.4567')
