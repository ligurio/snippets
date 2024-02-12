local msgpack = require('msgpack')
local decimal = require('decimal')

local dec = msgpack.encode(decimal.new(-12.34))
local hex = dec:gsub('.', function (c)
    return string.format('%02x', string.byte(c))
end)

print(hex)
