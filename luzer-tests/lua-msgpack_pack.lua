-- luarocks install lua-messagepack

_G.msgpack = nil
local mp = require( "msgpack" )
local luzer = require("luzer")

local function TestOneInput(buf)
    local packed = mp.pack(buf)
    assert(packed ~= nil)
    local unpacked_table = mp.unpack(packed)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
