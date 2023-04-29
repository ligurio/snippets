local parser = require("src.luacheck.parser")
local decoder = require("luacheck.decoder")
local luzer = require("luzer")

local function TestOneInput(buf)
    parser.parse(decoder.decode(buf))
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    -- corpus = script_path .. "djot/test",
    -- dict = script_path .. "djot.dict",
    artifact_prefix = "luacheck_parser_parse_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
