-- git clone https://github.com/openresty/lua-rds-parser
-- patch -p1 < lua-rds-parser.patch
-- make
-- lua rds_parser_fuzz.lua

local parser = require "rds_parser"
local luzer = require("luzer")

local function TestOneInput(buf)
	parser.parse(buf)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    -- corpus = script_path .. "corpus",
    corpus = "/home/sergeyb/sources/luzer-lua/tests/3rd-party/lua-rds-parser/corpus",
    -- dict = script_path .. "djot.dict",
    artifact_prefix = "rds_",
    max_total_time = 600,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
