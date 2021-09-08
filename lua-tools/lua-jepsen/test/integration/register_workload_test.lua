local fio = require('fio')
local log = require('log')
local t = require('luatest')
local helpers = require('test.helper')

local g = t.group()

-- {{{ Setup / teardown

g.before_all(function()
    -- Show logs from the etcd transport.
    -- note: log.cfg() is not available on tarantool 1.10
    pcall(log.cfg, {level = 3})

    -- Setup etcd.
    local etcd_path = tostring(os.getenv("ETCD_PATH")) .. '/etcd'
    if not fio.path.exists(etcd_path) then
        etcd_path = '/usr/bin/etcd'
        t.skip_if(not fio.path.exists(etcd_path), 'etcd missing, set ETCD_PATH')
    end
    g.datadir = fio.tempdir()
    g.etcd_process = helpers.Etcd:new({
        workdir = fio.tempdir('/tmp'),
        etcd_path = etcd_path,
        peer_url = 'http://127.0.0.1:17001',
        client_url = 'http://127.0.0.1:14001',
    })
    g.etcd_process:start()
end)

g.after_all(function()
    -- Teardown etcd.
    g.etcd_process:stop()
    fio.rmtree(g.etcd_process.workdir)
    fio.rmtree(g.datadir)
    g.etcd_process = nil
end)

g.before_each(function()
end)

g.after_each(function()
end)

-- }}} Setup / teardown

-- {{{ Helpers

-- }}} Helpers

-- {{{ new_instance

g.test_new_instance = function()
end

-- }}} new_instance
