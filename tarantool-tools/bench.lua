--
-- Run: taskset -c 1 tarantool perf.lua

local clock = require("clock")

local function elapsed(f, args)
    local begin_clock = clock.monotonic()
    f(unpack(args))
    return clock.monotonic() - begin_clock
end

-- Get the mean of numbers in a table.
local function calculate_mean(res)
	assert(type(res) == "table")
	local total_sum = 0
	for _, v in ipairs(res) do
		assert(type(v) == "number")
		total_sum = total_sum + v
    end
	return (total_sum / table.getn(res))
end

-- Get the median of a table.
local function calculate_median(res)
	assert(type(res) == "table")
	local sorted_res = table.copy(res)
	table.sort(sorted_res)
	local size = table.getn(sorted_res)
	if math.fmod(#sorted_res, 2) == 0 then
		return (sorted_res[size / 2] + sorted_res[(size / 2) + 1]) / 2
	else
		return sorted_res[math.ceil(size / 2)]
	end
end

local function min_max(res)
	assert(type(res) == "table")
	local min = res[1]
	local max = res[1]
	for _, v in ipairs(res) do
		if v < min then
		   min = v
		end
		if v > max then
			max = v
		end
	end
	return min, max
end

-- Get the standard deviation of a table
function calculate_stddev(res)
	local vm
	local sum = 0
	local mean = calculate_mean(t)
	for k, v in pairs(t) do
	    assert(type(v) == "number")
	   vm = v - mean
	   sum = sum + (vm * vm)
	end
	return math.sqrt(sum / (#t - 1))
end

local function bench(func, args, name)
	assert(type(func) == "function")
	assert(type(name) == "string")
	print("Running %s: ..............................")
    local res = {}
    local iterations = 10
    for _ = 1, iterations do
        table.insert(res, elapsed(func, args))
    end
	local min, max = min_max(res)
	local mean = calculate_mean(res)
	print(("Mean: %f, min %f, max %f"):format(mean, min, max))
end

return {
	bench = bench,
	calculate_mean = calculate_mean,
	calculate_median = calculate_median,
	min_max = min_max,
}
