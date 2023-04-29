local djot = require("djot")
local luzer = require("luzer")

local function TestOneInput(buf)
    local doc = djot.parse(buf)
    assert(doc ~= nil)
    djot.render_ast_pretty(doc)
    djot.render_ast_json(doc)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    corpus = script_path .. "djot/test",
    -- dict = script_path .. "djot.dict",
    artifact_prefix = "djot_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
