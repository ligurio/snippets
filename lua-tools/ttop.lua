#!/usr/bin/tarantool

-- Box requires permission to eval code:
-- box.schema.user.grant('guest', 'execute', 'universe')
--
-- box.cfg (configuration parameters)
-- 	https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_cfg/
-- box.slab (resources)
-- 	https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_slab/
-- box.info (replication configuration)
--	https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_info/
-- box.stat (request and network statistics)
-- 	https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_stat/
-- fiber.info (fibers statistics)
-- 	https://www.tarantool.io/en/doc/latest/reference/reference_lua/fiber/

local curses = require('curses')
local net_box = require('net.box')
local fiber = require('fiber')

local URI = '127.0.0.1:3301'

local function connect(uri)
    -- Check uri?
    print('Connecting to', uri)
    local conn = net_box.connect(uri)
    return conn
end

local function disconnect(conn)
    if conn ~= nil then
        conn:close()
    end

    return true
end

--[[
tarantool> box.slab.info()
---
- items_size: 342296
  items_used_ratio: 2.06%
  quota_size: 268435456
  quota_used_ratio: 12.50%
  arena_used_ratio: 3.3%
  items_used: 7040
  quota_used: 33554432
  arena_size: 33554432
  arena_used: 1104768
...
]]
local function stat_box_slab(conn)
    return conn:eval([[
        return {
	    check = box.slab.check(),
	    info = box.slab.info(),
	    stat = box.slab.stat(),
    ]])
end

local function stat_box_stat(conn)
    return conn:eval([[
        return box.stat.vinyl()
    ]])
end

--[[
---
- vinyl: []
  version: 1.10.11-0-gf0b0e7ecf
  id: 1
  ro: false
  status: running
  vclock: {1: 1}
  uptime: 1110
  lsn: 1
  memory: []
  cluster:
    uuid: 5cbba172-0db3-4b2e-8a0e-21399f1c851b
  pid: 1431313
  gc: []
  signature: 1
  replication:
    1:
      id: 1
      uuid: 54ae6f6b-1976-4378-8770-c9673ba6453f
      lsn: 1
  uuid: 54ae6f6b-1976-4378-8770-c9673ba6453f
...
]]
local function stat_box_info(conn)
    return conn:eval([[
        return box.info()
    ]])
end

--[[
  113:
    csw: 11
    backtrace:
    - C: '#0  0x415f4e40 in +63'
    - C: '#1  0x5146b4 in coio_wait+132'
    - C: '#2  0x4eb0cf in netbox_communicate+751'
    - L: send_and_recv in =[C] at line -1
    - L: send_and_recv_iproto in @builtin/box/net_box.lua at line 628
    - L: (unnamed) in @builtin/box/net_box.lua at line 770
    - C: '#3  0x525087 in lj_BC_FUNCC+52'
    - C: '#4  0x529448 in lua_pcall+120'
    - C: '#5  0x4f7a28 in luaT_call+24'
    - C: '#6  0x4f2949 in lua_fiber_run_f+89'
    - C: '#7  0x425331 in fiber_cxx_invoke(int (*)(__va_list_tag*), __va_list_tag*)+17'
    - C: '#8  0x50a040 in fiber_loop+48'
    - C: '#9  0x6e1e74 in coro_init+68'
    fid: 113
    memory:
      total: 516432
      used: 0
    name: 127.0.0.1:3301 (net.box)
]]
local function stat_fibers(conn)
    return conn:eval([[
        local fiber = require("fiber")
        return fiber.info()
    ]])
end

--[[
- log_nonblock: true   
  vinyl_run_count_per_level: 2 
  rows_per_wal: 500000
  feedback_host: https://feedback.tarantool.io
  readahead: 16320       
  log_level: 5   
  checkpoint_interval: 3600
  replication_connect_timeout: 30
  coredump: false 
  replication_sync_lag: 10
  replication_timeout: 1 
  wal_dir_rescan_delay: 2         
  feedback_enabled: true
  wal_max_size: 268435456  
  memtx_dir: .                 
  vinyl_memory: 134217728
  vinyl_max_tuple_size: 1048576
  background: false
  vinyl_dir: .
  vinyl_cache: 134217728
  vinyl_read_threads: 1
  too_long_threshold: 0.5
  vinyl_timeout: 60
  net_msg_max: 768
  listen: '3301'
  log_format: plain
  vinyl_bloom_fpr: 0.05
  wal_dir: .
  yheckpoint_cont: 2
  force_recovery: false
  memtx_max_tuple_size: 1048576
  hot_standby: false
  feedback_interval: 3600
  slab_alloc_factor: 1.05
  wal_mode: write
  worker_pool_threads: 4
  memtx_min_tuple_size: 16
  read_only: false
  vinyl_page_size: 8192
  memtx_memory: 268435456
  replication_skip_conflict: false
  vinyl_write_threads: 4
  vinyl_run_size_ratio: 3.5
  replication_sync_timeout: 300
]]
local function stat_box_cfg(conn)
    return conn:eval([[
        return box.cfg
    ]])
end

local function printf(fmt, ...)
  return print(string.format (fmt, ...))
end

-- To display Lua errors, we must close curses to return to
-- normal terminal mode, and then write the error to stdout.
local function err(err)
  curses.endwin()
  print("Caught an error:")
  print(debug.traceback (err, 2))
  os.exit(2)
end

local function draw_screen(conn, stdscr)
    local box_cfg = stat_box_cfg(conn)
    local box_info = stat_box_info(conn)
    local box_info = stat_box_info(conn)
    local fiber_info = stat_fibers(conn)
    -- local box_slab = stat_box_slab(conn)

    -- Create a background.
    local ncols = curses.cols()  
    local nrows = curses.lines()  
     
    -- Create a top and bottom color strip.
    stdscr:attron(a_rw)		-- set the fore/background colors  
    for i=0, (ncols - 1), 1 do	-- write a top and bottom strip  
	 stdscr:mvaddstr(0, i, " ")  
	 stdscr:mvaddstr(nrows -1, i, " ")  
    end  

    -- General information on header.
    stdscr:mvaddstr(0, 0, 'Simple Tarantool monitoring')
    stdscr:mvaddstr(0, 30, tostring(box_info.version))
    stdscr:mvaddstr(0, 55, 'Uptime: ' .. tostring(box_info.uptime))
    stdscr:mvaddstr(0, 70, 'LSN: ' .. tostring(box_info.uptime))
    stdscr:mvaddstr((nrows -1), 0, 'Key Commands: q - to quit.')

    -- Add the main screen static text.
    stdscr:mvaddstr(2, 15, 'Common settings')
    stdscr:mvaddstr(4, 3, 'memtx_memory: ' .. box_cfg.memtx_memory)
    stdscr:mvaddstr(5, 3, 'WAL mode: ' .. box_cfg.wal_mode)
    stdscr:mvaddstr(6, 3, 'net_msg_max: ' .. tostring(box_cfg.net_msg_max))

    stdscr:mvaddstr(8, 15, 'Replication settings')
    stdscr:mvaddstr(10, 3, 'replication_connect_timeout: ' .. box_cfg.replication_connect_timeout)
    stdscr:mvaddstr(11, 3, 'replication_sync_lag: ' .. box_cfg.replication_sync_lag)
    stdscr:mvaddstr(12, 3, 'replication_sync_timeout: ' .. box_cfg.replication_sync_timeout)

    stdscr:mvaddstr(14, 15, 'Fibers')
    local start_line = 16
    for i, f in pairs(fiber_info) do
        stdscr:mvaddstr(start_line, 3, string.format("%d: %5d %s", f.fid, f.csw, f.name))
        start_line = start_line + 1
    end
end

local function screen_init()
    curses.initscr()  
    curses.echo(false) 	-- not noecho!
    curses.cbreak()
    curses.nl(false)	-- not nonl!

    -- Setup color pairs and attribute variables.
    if os.getenv('NO_COLOR') == nil then
    	curses.start_color()
    end
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_WHITE)  
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)  
    curses.init_pair(3, curses.COLOR_BLUE, curses.COLOR_BLACK)  
    curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)  
    curses.init_pair(5, curses.COLOR_RED, curses.COLOR_BLACK)  
    curses.init_pair(6, curses.COLOR_GREEN, curses.COLOR_BLACK)  

    a_rw = curses.color_pair(1)  
    a_white = curses.color_pair(2)  
    a_blue = curses.color_pair(3)  
    a_yellow = curses.color_pair(4)  
    a_red = curses.color_pair(5)  
    a_green = curses.color_pair(6)  

    local stdscr = curses.stdscr() -- the screen object  
    stdscr:clear()  

    return stdscr
end


local function main()
    local conn = connect(URI)		
    local stdscr = screen_init()

    curses.timeout(3000)
    local c
    while c ~= 113 do -- 113 = q, quit
        stdscr:clear()  
        draw_screen(conn, stdscr)
	c = stdscr:getch()  
    end  
    stdscr:refresh()

    curses.endwin()  
    disconnect(conn)
end

xpcall(main, err)
