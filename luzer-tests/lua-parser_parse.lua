local parser = require("lua-parser.parser")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ast = parser.parse(buf)
    -- Fix setmaxstack().
    -- assert(ast ~= nil)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    artifact_prefix = "lua-parser_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
