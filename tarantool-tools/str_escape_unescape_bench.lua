-- Run: taskset 0x1 ./build/src/tarantool str_escape_unescape_bench.lua
-- Based on https://github.com/mpx/lua-cjson/blob/master/tests/bench.lua

local uri = require("uri")
local clock = require("clock")

local str_escape = uri.str_escape
local str_unescape = uri.str_unescape

local encode_sample = "hello こんにちは สวัสดี"
local decode_sample = "hello+%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF+%E0%B8%AA%E0%B8%A7%E0%B8%B1%E0%B8%AA%E0%B8%94%E0%B8%B5"

local cycles = 10^4
local start = clock.monotonic()
for i = 1, cycles do
    str_escape(encode_sample)
end
local encode_time = cycles / (clock.monotonic() - start)

local start = clock.monotonic()
for i = 1, cycles do
    str_unescape(decode_sample)
end
local decode_time = cycles / (clock.monotonic() - start)

print(("str_escape %f ops/sec"):format(encode_time))
print(("str_unescape %f ops/sec"):format(decode_time))

--[[
local function average(t)
    local total = 0
    for _, v in ipairs(t) do
        total = total + v
    end
    return total / #t
end

function benchmark(tests, seconds, rep)
    local function bench(func, iter)
        local t = clock.monotonic()
        for i = 1, iter do
            func(i)
        end
        t = clock.monotonic() - t

        -- Don't trust any results when the run lasted for less than a
        -- millisecond - return nil.
        if t < 0.001 then
            return nil
        end

        return (iter / t)
    end

    -- Roughly calculate the number of interations required
    -- to obtain a particular time period.
    local function calc_iter(func, seconds)
        local iter = 1
        local rate
        -- Warm up the bench function first.
        func()
        while not rate do
            rate = bench(func, iter)
            iter = iter * 10
        end
        return math.ceil(seconds * rate)
    end

    local test_results = {}
    for name, func in pairs(tests) do
        -- k(number), v(string)
        -- k(string), v(function)
        -- k(number), v(function)
        if type(func) == "string" then
            name = func
            func = _G[name]
        end

        local iter = calc_iter(func, seconds)

        local result = {}
        for i = 1, rep do
            result[i] = bench(func, iter)
        end

        -- Remove the slowest half (round down) of the result set.
        table.sort(result)
        for i = 1, math.floor(#result / 2) do
            table.remove(result, 1)
        end

        test_results[name] = average(result)
    end

    return test_results
end

local tests = {
    encode = function() str_escape(encode_sample) end,
    decode = function() str_unescape(decode_sample) end,
}

local results = benchmark(tests, 0.1, 5)

for k, v in pairs(results) do
    print(("%s\t%d"):format(k, v))
end
]]
