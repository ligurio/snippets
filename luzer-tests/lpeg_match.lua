-- https://www.inf.puc-rio.br/~roberto/lpeg/

local luzer = require("luzer")
local has_lpeg, _ = pcall(require, "lpeg")

if has_lpeg == false then
    print("lpeg is not found")
    os.exit(1)
end

local MAX_STACK_DEPTH = 10000

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local pattern = fdp:consume_string()
    local subject = fdp:consume_string()
    local str = fdp:consume_string()

	lpeg.setmaxstack(MAX_STACK_DEPTH)
	local ok, p = pcall(lpeg.match, pattern, subject)
	if ok == true then
	    assert(p ~= nil, "pattern is nil")
	    p:match(str)
	end
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    corpus = script_path .. "lpeg",
}
luzer.Fuzz(TestOneInput, nil, args)
