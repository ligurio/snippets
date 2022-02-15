local inspect = require('inspect')

function trace (event)
  local s = debug.getinfo(2)
  print(inspect.inspect(s))
end
    
local hello = function ()
    --print("return")
    return 1
end

debug.sethook(trace, "r")
hello()
