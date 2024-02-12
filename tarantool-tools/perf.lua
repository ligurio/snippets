--[[
-- measure serialization time
-- run: taskset -c 1 tarantool perf.lua
]]

local clock = require('clock')

local function elapsed(f, n)
    local t0 = clock.monotonic()
    for i = 1, n do
        f()
    end
    local t1 = clock.monotonic()
    return t1 - t0
end

-- Get the mean of a table
function calculate_mean(t)
  local sum = 0
  local count= 0
  for k, v in pairs(t) do
    if type(v) == 'number' then
      sum = sum + v
    end
  end

  return (sum/#t)
end

-- Get the median of a table.
function calculate_median(t)
  local temp = {}
  -- deep copy table so that when we sort it, the original is unchanged
  -- also weed out any non numbers
  for k, v in pairs(t) do
    if type(v) == 'number' then
      table.insert(temp, v)
    end
  end
  table.sort(temp)
  -- If we have an even number of table elements or odd.
  if math.fmod(#temp,2) == 0 then
    -- return mean value of middle two elements
    return (temp[#temp/2] + temp[(#temp/2)+1]) / 2
  else
    -- return middle element
    return temp[math.ceil(#temp/2)]
  end
end

-- Get the standard deviation of a table
function calculate_stddev(t)
  local vm
  local sum = 0
  local mean = calculate_mean(t)
  for k, v in pairs(t) do
    if type(v) == 'number' then
      vm = v - mean
      sum = sum + (vm * vm)
    end
  end

  return math.sqrt(sum/(#t - 1))
end

local function timeit(f, name)
    print('======================================')
    print(name)
    print('======================================')
    local res = {}
    local iterations = 10
    local elapsed_time = 0
    local repetitions = 150000
    for j = 1, iterations do
        -- warming
        for i = 1, 100 do f() end
        -- measurement
        elapsed_time = elapsed(f, repetitions)
        table.insert(res, elapsed_time)
        print(string.format("%-2d - %f sec / %d repetitions", j, elapsed_time, repetitions))
    end
    print(string.format("time mean   %f", calculate_mean(res)))
    print(string.format("time median %f", calculate_median(res)))
    print(string.format("time stddev %f", calculate_stddev(res)))
end

local t = {{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
timeit(function()
           local console = require('console') 
           console.set_default_output('yaml')
           return console.eval(tostring(t))
       end, 'serializer console yaml')
timeit(function()
           local console = require('console') 
           console.set_default_output('lua')
           return console.eval(tostring(t))
       end, 'serializer console lua')
timeit(function()
           local serializer = require('json') 
           serializer.cfg({encode_max_depth = 64})
           return serializer.encode(t)
       end, 'serializer json')
timeit(function()
           local serializer = require('yaml')
           serializer.cfg({encode_max_depth = 64})
           return serializer.encode(t)
       end, 'serializer yaml')
timeit(function()
           local serializer = require('msgpack')
           serializer.cfg({encode_max_depth = 64})
           return serializer.encode(t)
       end, 'serializer msgpack')
timeit(function()
           local serializer = require('msgpackffi')
           return serializer.encode(t)
       end, 'serializer msgpackffi')
