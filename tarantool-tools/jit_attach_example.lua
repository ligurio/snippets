assert(type(jit) == "table", "jit module is not available")

-- https://www.tarantool.io/en/doc/latest/reference/tooling/luajit_getmetrics/#luajit-getmetrics-tablevalues

local jit_trace_aborted = 0;
local jit_trace_recorded = 0;

-- https://ligurio.github.io/lua-c-manual-pages/lua_CFunction.3.html

jit.opt.start('hotloop=1')

local trace_cb = function(what, tr, func, pc, otr, oex)
    -- what: [ "flush", "start", "stop", "abort" ]
	if what == "abort" then
        jit_trace_abort = jit_trace_abort + 1
	end
end

local record_cb = function(tr, func, pc, depth, callee)
    jit_trace_recorded = jit_trace_recorded + 1
end

jit.flush()
jit.attach(trace_cb, "trace")
jit.attach(record_cb, "record")

local expected = 1
local result
for _ = 1, 4 do
    result = ({[0] = 1, [-0] = 2})[0]
end
local metrics = misc.getmetrics()
assert(result == 2)

jit.attach(trace_cb)
jit.attach(record_cb)

print(("LuaJIT jit.attach: recorded traces: %d"):format(jit_trace_recorded))
print(("LuaJIT jit.attach: aborted traces: %d"):format(jit_trace_aborted))

print(("Tarantool misc.getmetrics().jit_trace_num: %s"):format(metrics.jit_trace_num))
print(("Tarantool misc.getmetrics().jit_trace_abort: %s"):format(metrics.jit_trace_abort))
print(("Tarantool misc.getmetrics().jit_snap_restore: %s"):format(metrics.jit_snap_restore))
