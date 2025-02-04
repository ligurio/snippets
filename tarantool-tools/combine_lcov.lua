-- https://lunarmodules.github.io/luacov/doc/modules/luacov.stats.html

local luacov_stats = require("luacov.stats")
local fio = require("fio")

local source = arg[1]
local dest = arg[2]

if not source or
   not dest or
   not fio.path.exists(source) or
   not fio.path.exists(dest) then
    print("Please specify paths to source and destination stats files:")
    print(("tarantool %s luacov.stats.out_source luacov.stats.out_dest"):format(arg[0]))
    os.exit(1)
end

local source_stats = luacov_stats.load(source)
luacov_stats.save(dest, source_stats)
