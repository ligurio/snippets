local checks = require('checks')
local errors = require('errors')
local fiber = require('fiber')
local log = require('log')

local WorkloadError = errors.new_class('WorkloadError', {capture_stack = false})
local WorkerError = errors.new_class('WorkerError', {capture_stack = false})

local function create_ops_channel(ch, gen)
    for _, v in gen do
        ch:put(v)
    end
end

local function run_worker(fn_client_invoke, ch)
    local op = ch:get()
    if op == nil then
        return nil, WorkerError:new('Channel is empty')
    end
    log.info('worker %s %s %d', op.type, op.f, op.v)
    local ok, err = pcall(fn_client_invoke, op)
    if err ~= nil then
        return nil, WorkerError:new('Operation failed: %s', err)
    end
    assert(ok ~= nil)
    assert(type(ok) == 'table')
    log.info('worker %s %s %d', op.type, op.f, op.v)
end

local function run_test(w, test)
    checks('table', 'table|nil')

    if type(w.client.open) ~= 'function' or
       type(w.client.setup) ~= 'function' or
       type(w.client.invoke) ~= 'function' or
       type(w.client.teardown) ~= 'function' or
       type(w.client.close) ~= 'function' then
        return nil, WorkloadError:new('Client has a wrong interface')
    end

    local _, err = pcall(w.client.setup, test)
    if err ~= nil then
        return nil, err
    end

    local _, err = pcall(w.client.open, test)
    if err ~= nil then
        return nil, err
    end

    -- TODO: start 'test.concurrency' workers
    local ch_ops = fiber.channel()
    local fiber_ops = fiber.create(create_ops_channel, ch_ops, w.generator)
    fiber_ops:set_joinable(true)
    local _, err = pcall(run_worker, w.client.invoke, ch_ops)
    if err ~= nil then
        return nil, err
    end

    -- TODO: check time and break if overall test timeout is reached
    if ch_ops:empty() then
        fiber_ops:join()
        fiber_ops:cancel()
        ch_ops:close()
    end

    local _, err = pcall(w.client.close, test)
    if err ~= nil then
        return nil, err
    end

    local _, err = pcall(w.client.teardown, test)
    if err ~= nil then
        return nil, err
    end
end

return {
    run_test = run_test,
}
