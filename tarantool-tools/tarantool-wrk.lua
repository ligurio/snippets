#!/usr/bin/tarantool
--
-- tarantool-wrk.lua: a wrk/wrk2-style HTTP load generator for
-- Tarantool.
--
-- Concurrency is provided by Tarantool fibers: each of the -c
-- connections is a dedicated worker fiber issuing sequential
-- requests with its own `http.client` (libcurl) handle. wrk2's
-- fixed-rate (-R) mode is implemented with global slot
-- scheduling. The --json summary is serialized with `json.encode`,
-- and the histogram math runs on LuaJIT.
--
-- Usage:
--   tarantool tarantool-wrk.lua [options] <url>
--     -c, --connections N     number of connections (= worker fibers)
--     -t, --threads N         accepted for wrk compatibility, ignored
--     -d, --duration T        test duration, e.g. 10s, 2m, 500ms (default 10s)
--     -R, --rate N            fixed request rate per second (wrk2 mode)
--     -T, --timeout S         per-request timeout in seconds (default 5)
--     -H, --header "K: V"     add a header (repeatable)
--     -m, --method M          HTTP method (default GET)
--     -b, --body B            request body
--     -s, --script F          load a wrk-compatible Lua test script
--         --latency           print the latency distribution
--         --json              print the summary as a JSON object
--     -h, --help              show this help
--
-- HTTP/1.1 pipelining (wrk2 -P) and keep-alive connection reuse
-- are not supported by `http.client`: it creates and destroys a
-- libcurl easy handle per request, so every request uses a fresh
-- TCP connection. The -c option therefore bounds the number of
-- concurrent in-flight requests (one per worker fiber), not the
-- number of open sockets.
--
-- Test scripts: -s script.lua may set the global `wrk` table
-- (wrk.method, wrk.path, wrk.headers, wrk.body, wrk.host, wrk.port,
-- wrk.scheme) and define the global functions `request()`,
-- `response(status, headers, body)`, `setup()` and
-- `done(summary)`. request() returns nil to use wrk.* defaults or
-- a table {method=, path=, headers=, body=}; the helper
-- `wrk.format(method, path, headers, body)` builds such a table.

local http = require('http.client')
local fiber = require('fiber')
local clock = require('clock')
local json = require('json')
local log = require('log')

-- Keep the report clean: drop Tarantool's own INFO noise such as
-- "entering the event loop". Test scripts may override this if
-- they log.
log.level('warn')

local DEFAULT_DURATION = 10
local DEFAULT_CONNECTIONS = 10
local DEFAULT_TIMEOUT = 5

-- Per-request options for http.client. These must be passed with every
-- request: http.new() only understands max_connections/max_total_connections
-- and would silently ignore the timeout. http.client does not pool
-- connections, so keep-alive options would serve no purpose here.
local timeout = DEFAULT_TIMEOUT

-- Latency histogram: fixed-width buckets of 0.1 ms up to LATENCY_MAX,
-- plus an overflow counter. Fixed memory regardless of request rate.
local LATENCY_STEP = 0.0001 -- 0.1 ms
local LATENCY_MAX = 10.0    -- 10 s
local N_BUCKETS = math.floor(LATENCY_MAX / LATENCY_STEP) + 1
local MEBIBYTE = 1024 * 1024

local stats = {
    bytes = 0,
    err = 0,
    hist = {},
    max = 0,
    n = 0,
    overflow = 0,
    sec_hist = {},
    start = 0,
    sum = 0,
    sum2 = 0,
}

for i = 1, N_BUCKETS do
    stats.hist[i] = 0
end

-- Global pacing state shared by all worker fibers. Tarantool is a single
-- cooperative scheduler, so plain field updates are atomic between fibers.
local stop = false
local cond = fiber.cond()
local next_slot = 0
local spacing = 0

local function printf(fmt, ...)
    print(string.format(fmt, ...))
end

local function usage()
    print([[
Usage: tarantool tarantool-wrk.lua [options] <url>

  -c, --connections N     number of connections (= worker fibers)
  -t, --threads N         accepted for wrk compatibility, ignored
  -d, --duration T        test duration, e.g. 10s, 2m, 500ms (default 10s)
  -R, --rate N            fixed request rate per second (wrk2 mode)
  -T, --timeout S         per-request timeout in seconds (default 5)
  -H, --header "K: V"     add a header (repeatable)
  -m, --method M          HTTP method (default GET)
  -b, --body B            request body
  -s, --script F          load a wrk-compatible Lua test script
      --latency           print the latency distribution
      --json              print the summary as a JSON object
  -h, --help              show this help
]])
end

local function parse_duration(str)
    local num, unit = str:match('^(%d+%.?%d*)(.*)$')
    num = tonumber(num)
    if num == nil then
        return nil
    end
    if unit == '' or unit == 's' then
        return num
    elseif unit == 'ms' then
        return num / 1000
    elseif unit == 'm' then
        return num * 60
    elseif unit == 'h' then
        return num * 3600
    end
    return nil
end

local function parse_args(args)
    local opts = {
        connections = DEFAULT_CONNECTIONS,
        duration = DEFAULT_DURATION,
        timeout = DEFAULT_TIMEOUT,
        headers = {},
        latency = false,
        json = false,
    }
    local url
    local i, n = 1, #args

    local function next_value(flag)
        i = i + 1
        local v = args[i]
        if v == nil then
            error(('option %s requires a value'):format(flag))
        end
        return v
    end

    while i <= n do
        local a = args[i]
        if a == '-h' or a == '--help' then
            usage()
            os.exit(0)
        elseif a == '-c' or a == '--connections' then
            opts.connections = tonumber(next_value(a))
        elseif a == '-t' or a == '--threads' then
            opts.threads = tonumber(next_value(a))
        elseif a == '-d' or a == '--duration' then
            opts.duration = parse_duration(next_value(a))
            if opts.duration == nil then
                error(('invalid duration: %s'):format(args[i]))
            end
        elseif a == '-R' or a == '--rate' then
            opts.rate = tonumber(next_value(a))
        elseif a == '-T' or a == '--timeout' then
            opts.timeout = tonumber(next_value(a))
        elseif a == '-H' or a == '--header' then
            opts.headers[#opts.headers + 1] = next_value(a)
        elseif a == '-m' or a == '--method' then
            opts.method = next_value(a)
        elseif a == '-b' or a == '--body' then
            opts.body = next_value(a)
        elseif a == '-s' or a == '--script' then
            opts.script = next_value(a)
        elseif a == '--latency' then
            opts.latency = true
        elseif a == '--json' then
            opts.json = true
        elseif a:sub(1, 1) == '-' then
            error(('unknown option: %s'):format(a))
        else
            url = a
        end
        i = i + 1
    end
    return opts, url
end

-- Split an URL into scheme, host, port and path. IPv6 literals are not
-- handled, plain host:port is expected.
local function parse_url(url)
    local scheme, rest = url:match('^(%a+)://(.*)$')
    scheme = scheme or 'http'
    if rest == nil then
        rest = url
    end
    local hp, path = rest:match('^([^/]*)(/.*)$')
    if hp == nil then
        hp, path = rest, '/'
    end
    local host, port = hp:match('^(.*):(%d+)$')
    if host == nil then
        host, port = hp, 80
    else
        port = tonumber(port)
    end
    return scheme, host, port, path
end

-- The `wrk` table is a global so that loaded test scripts can mutate it,
-- exactly like real wrk test scripts do.
local function init_wrk(opts, url)
    local scheme, host, port, path = parse_url(url)
    _G.wrk = {
        scheme = scheme,
        host = host,
        port = port,
        path = path,
        method = (opts.method or 'GET'):upper(),
        headers = {},
        body = opts.body,
    }
    wrk.format = function(method, path, headers, body)
        return {
            method = method or wrk.method,
            path = path or wrk.path,
            headers = headers or wrk.headers,
            body = body,
        }
    end
    for _, hdr in ipairs(opts.headers) do
        local k, v = hdr:match('^([^:]+):%s*(.*)$')
        if k ~= nil then
            wrk.headers[k] = v
        end
    end
end

local function load_script(path)
    if path == nil then
        return
    end
    local chunk, err = loadfile(path)
    if chunk == nil then
        error(err)
    end
    local ok, err2 = pcall(chunk)
    if not ok then
        error(('test script failed: %s'):format(tostring(err2)))
    end
end

local function make_request()
    local req = _G.request and _G.request()
    local method = (req and req.method) or wrk.method or 'GET'
    local path = (req and req.path) or wrk.path or '/'
    local headers = (req and req.headers) or wrk.headers
    local body = (req and req.body)
    if body == nil then
        body = wrk.body
    end
    if type(body) == 'table' then
        body = json.encode(body)
    end
    local url = wrk.scheme .. '://' .. wrk.host .. ':' .. wrk.port .. path
    return method:upper(), url, headers, body
end

-- Record one completed request. t0 is the monotonic request start, used to
-- bucket the request rate by wall-clock second of the test.
local function record(dt, t0)
    stats.n = stats.n + 1
    stats.sum = stats.sum + dt
    stats.sum2 = stats.sum2 + dt * dt
    if dt > stats.max then
        stats.max = dt
    end
    local b = math.floor(dt / LATENCY_STEP) + 1
    if b <= N_BUCKETS then
        stats.hist[b] = stats.hist[b] + 1
    else
        stats.overflow = stats.overflow + 1
    end
    local sec = math.floor(t0 - stats.start) + 1
    stats.sec_hist[sec] = (stats.sec_hist[sec] or 0) + 1
end

local function worker(client)
    local req_opts = { timeout = timeout }
    if _G.setup then
        _G.setup()
    end
    while true do
        if stop then
            break
        end
        -- wrk2 pacing: grab the next global slot, sleep until it fires.
        if spacing > 0 then
            local slot = next_slot
            next_slot = slot + spacing
            local wait = slot - clock.monotonic()
            if wait > 0 then
                cond:wait(wait)
            end
        end
        -- Never fire a request that was scheduled during the wind-down.
        if stop then
            break
        end
        local method, url, headers, body = make_request()
        req_opts.headers = headers
        local t0 = clock.monotonic()
        -- The client either returns a response whose `reason` is a curl
        -- error string (status 408/444/495/595) or raises; treat anything
        -- other than a real HTTP status with Ok/Unknown reason as failure.
        local ok, resp = pcall(client.request, client, method, url, body, req_opts)
        local dt = clock.monotonic() - t0
        if ok and resp.status >= 100 and resp.status < 600 and
           (resp.reason == 'Ok' or resp.reason == 'Unknown') then
            record(dt, t0)
            stats.bytes = stats.bytes + (resp.body and #resp.body or 0)
            if _G.response then
                _G.response(resp.status, resp.headers, resp.body)
            end
        else
            stats.err = stats.err + 1
        end
    end
end

-- Percentiles, mean, stdev and the share of samples within avg +/- stdev.
local function latency_stats()
    local n = stats.n
    if n == 0 then
        return { avg = 0, stdev = 0, max = 0, p50 = 0, p75 = 0, p90 = 0,
                 p99 = 0, in_stdev = 1 }
    end
    local avg = stats.sum / n
    local var = stats.sum2 / n - avg * avg
    if var < 0 then
        var = 0
    end
    local stdev = math.sqrt(var)
    local lo, hi = avg - stdev, avg + stdev
    local in_band = 0
    local p50, p75, p90, p99
    local t50, t75, t90, t99 = 0.5 * n, 0.75 * n, 0.9 * n, 0.99 * n
    local acc = 0
    for i = 1, N_BUCKETS do
        local c = stats.hist[i]
        if c > 0 then
            local mid = (i - 0.5) * LATENCY_STEP
            if mid >= lo and mid <= hi then
                in_band = in_band + c
            end
            acc = acc + c
            if p50 == nil and acc >= t50 then p50 = mid end
            if p75 == nil and acc >= t75 then p75 = mid end
            if p90 == nil and acc >= t90 then p90 = mid end
            if p99 == nil and acc >= t99 then p99 = mid end
        end
    end
    if p99 == nil then p99 = stats.max end
    if p90 == nil then p90 = stats.max end
    if p75 == nil then p75 = stats.max end
    if p50 == nil then p50 = stats.max end
    return {
        avg = avg, stdev = stdev, max = stats.max,
        p50 = p50, p75 = p75, p90 = p90, p99 = p99,
        in_stdev = in_band / n,
    }
end

-- Per-second request rate: mean, stdev, max and the share of seconds
-- within avg +/- stdev.
local function rate_stats()
    local cnt, sum, sum2, maxc = 0, 0, 0, 0
    for _, c in pairs(stats.sec_hist) do
        cnt = cnt + 1
        sum = sum + c
        sum2 = sum2 + c * c
        if c > maxc then
            maxc = c
        end
    end
    if cnt == 0 then
        return { avg = 0, stdev = 0, max = 0, in_stdev = 1 }
    end
    local avg = sum / cnt
    local var = sum2 / cnt - avg * avg
    if var < 0 then
        var = 0
    end
    local stdev = math.sqrt(var)
    local lo, hi = avg - stdev, avg + stdev
    local in_band = 0
    for _, c in pairs(stats.sec_hist) do
        if c >= lo and c <= hi then
            in_band = in_band + 1
        end
    end
    return { avg = avg, stdev = stdev, max = maxc, in_stdev = in_band / cnt }
end

local function main()
    local opts, url = parse_args(arg)
    if url == nil then
        usage()
        os.exit(1)
    end
    if opts.connections == nil or opts.connections < 1 then
        error('connections must be a positive integer')
    end
    timeout = opts.timeout or DEFAULT_TIMEOUT
    if opts.rate ~= nil and opts.rate > 0 then
        spacing = 1 / opts.rate
    end

    init_wrk(opts, url)
    load_script(opts.script)

    stats.start = clock.monotonic()
    next_slot = stats.start

    local done_chan = fiber.channel(opts.connections)
    for _ = 1, opts.connections do
        fiber.create(function()
            local ok, err = pcall(function()
                worker(http.new())
            end)
            if not ok then
                printf('worker error: %s', tostring(err))
            end
            done_chan:put(true)
        end)
    end

    fiber.sleep(opts.duration)
    -- Duration is measured up to the stop point, not including the short
    -- wind-down while in-flight requests drain.
    local stop_time = clock.monotonic()
    stop = true
    cond:broadcast()

    -- Wait for workers to wrap up, but bound the wind-down to a second so
    -- the reported duration stays close to -d. In-flight requests beyond
    -- that are dropped, like wrk closes its connections at the end.
    local drain = math.min(opts.timeout, 1)
    local deadline = clock.monotonic() + drain
    for _ = 1, opts.connections do
        local left = deadline - clock.monotonic()
        if left <= 0 then
            break
        end
        done_chan:get(left)
    end

    local duration = stop_time - stats.start
    local lat = latency_stats()
    local rps = stats.n / duration
    local rate = rate_stats()
    local bytes = stats.bytes

    local summary = {
        url = url,
        duration = duration,
        connections = opts.connections,
        threads = opts.threads,
        rate = opts.rate,
        requests = stats.n,
        errors = stats.err,
        requests_per_sec = math.floor(rps * 100 + 0.5) / 100,
        bytes = bytes,
        transfer_per_sec = math.floor(bytes / duration * 100 + 0.5) / 100,
        latency = {
            avg_ms = lat.avg * 1000,
            stdev_ms = lat.stdev * 1000,
            max_ms = lat.max * 1000,
            p50_ms = lat.p50 * 1000,
            p75_ms = lat.p75 * 1000,
            p90_ms = lat.p90 * 1000,
            p99_ms = lat.p99 * 1000,
        },
    }
    if _G.done then
        _G.done(summary)
    end

    if opts.json then
        print(json.encode(summary))
        return
    end

    printf('Running %0.1fs test @ %s', duration, url)
    printf('  %d worker fibers and %d connections',
           opts.threads or opts.connections, opts.connections)
    printf('  Thread Stats   Avg      Stdev     Max   +/- Stdev')
    printf('    Latency     %6.2fms  %6.2fms  %6.2fms  %6.2f%%',
           lat.avg * 1000, lat.stdev * 1000, lat.max * 1000, lat.in_stdev * 100)
    printf('    Req/Sec     %8.2f  %6.2f  %8d  %6.2f%%',
           rate.avg, rate.stdev, rate.max, rate.in_stdev * 100)
    if opts.latency then
        print('  Latency Distribution')
        printf('     50%%    %0.2fms', lat.p50 * 1000)
        printf('     75%%    %0.2fms', lat.p75 * 1000)
        printf('     90%%    %0.2fms', lat.p90 * 1000)
        printf('     99%%    %0.2fms', lat.p99 * 1000)
    end
    if stats.err > 0 then
        printf('  %d errors', stats.err)
    end
    printf('  %d requests in %0.2fs, %0.2fMB read', stats.n, duration, bytes / MEBIBYTE)
    printf('Requests/sec:   %0.2f', rps)
    printf('Transfer/sec:   %0.2fMB', (bytes / duration) / MEBIBYTE)
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
    print('Caught an error:')
    print(err)
    os.exit(2)
end
