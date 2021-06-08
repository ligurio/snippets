-- https://keplerproject.github.io/luasql/manual.html
-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/fiber/
-- https://gist.github.com/sergos/c2dae39bf1ac47519356de23601ea7f4
-- https://aphyr.com/posts/316-jepsen-etcd-and-consul
-- https://luafun.github.io/basic.html

local fiber = require('fiber')
local http = require('http.client').new()
local fun = require('fun')
local log = require('log')
local net_box = require('net.box')
local math = require('math')

math.randomseed(os.time())

local op_channel = fiber.channel(1000)
local res_channel = fiber.channel(1000)  
local n_fibers = 10
local n_ops = 1000

box.cfg{
  listen = 3301,
}

box.once('schema', function()
   box.schema.space.create('test')
   box.space.test:create_index('primary')
   box.schema.user.grant('guest', 'read,write,execute', 'universe')
end)

local function r()
    return {f = 'read', v = nil}
end

local function w()
    return {f = 'write', v = math.random(1, 10)}
end

local function cas()
    return {f = 'cas', v = {math.random(1, 10), math.random(1, 10)}}
end

local function client()
  fiber.sleep(math.random(1, 4))
  local conn = net_box.connect('127.0.0.1:3301')
  conn:ping()
  while true do
    if op_channel:is_empty() then
      print('client closes connection')
      conn:close()
      return
    end
    fiber.yield()
    local op = op_channel:get()
    local ok
    print('client', op.f)
    if op.f == 'write' then
      ok = pcall(conn.space.test:replace({1, op.v}))
      res_channel:put({status = ok, f = 'write'})
    elseif op.f == 'read' then
      ok = pcall(conn.space.test:select(1))
      res_channel:put({status = ok, f = 'read'})
    end
  end
end

local function process_results()
  -- read results
  local processed = 0
  while processed ~= n_ops do
    local res = res_channel:get()
    print('res', res.status, res.f)
    processed = processed + 1
  end
  print('FIN')
end

local function main()
  -- generate operations
  local gen = fun.rands(0, 10):map(function(x) return x == 0 and r or w end):take(n_ops):totable()
  for _, op in pairs(gen) do
    local op = op()
    op_channel:put(op)
    print('gen operation', op.f)
  end

  -- start clients
  for i = 1, n_fibers, 1 do
    fiber.create(client)
  end

  -- start processing
  fiber.create(process_results)
end

main()
