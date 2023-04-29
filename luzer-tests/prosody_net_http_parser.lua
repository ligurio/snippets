local http_parser = require "net.http.parser";
local luzer = require("luzer")

local function test_stream(stream)
	local success_cb = spy.new(function (packet)
		assert.is_table(packet);
		if packet.body ~= false then
			assert.is_equal(expect.body, packet.body);
		end
	end);

	local parser = http_parser.new(success_cb, error, stream:sub(1,4) == "HTTP" and "client" or "server")
	for chunk in stream:gmatch("."..string.rep(".?", parser_input_bytes-1)) do
		parser:feed(chunk);
	end
end

local function TestOneInput(buf)
    test_stream(buf)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    -- corpus = script_path .. "djot/test",
    -- dict = script_path .. "djot.dict",
    artifact_prefix = "prosody_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
