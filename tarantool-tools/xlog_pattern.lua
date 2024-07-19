-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/xlog/
-- https://www.tarantool.io/en/doc/latest/reference/tooling/tt_cli/cat/

local xlog = require('xlog')

local xlog_file = '00000000000000521976.xlog'

local t = {}
for _, v in xlog.pairs(xlog_file) do
    table.insert(t, setmetatable(v, { __serialize = "map"}))
end

for _, v in pairs(t) do
    print(v['type'])
end
