local register_workload = require('register')
local fun = require('fun')
local inspect = require('inspect')

local g2 = fun.range(5):take(3)
for a, b in g2 do
    print(inspect.inspect(a), inspect.inspect(b), inspect.inspect(c))
end
