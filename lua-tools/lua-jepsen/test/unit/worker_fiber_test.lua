local clock = require('clock')
local log = require('log')

local yield = coroutine.yield
local resume = coroutine.resume
local co = coroutine.create

local t = require('luatest')
local g = t.group()

-- Skynet 1M threads microbenchmark
-- https://github.com/atemerev/skynet
local function skynet(num, size)
  if size == 1 then
    return yield(num)
  end

  size = size / 10
  local acc = 0

  for i = 0, 9 do
    local _, result = resume(co(skynet), num + i * size, size)
    acc = acc + result
  end

  return yield(acc)
end

g.test_skynet_coroutine = function()
    local time_begin = clock.monotonic()
    local _, result = resume(co(skynet), 0, 1000000)
    local total_time = clock.monotonic() - time_begin
    log.info('%s, time: %f sec', result, total_time)
end

g.test_skynet_fiber = function()
    t.skip('Unsupported')
end
