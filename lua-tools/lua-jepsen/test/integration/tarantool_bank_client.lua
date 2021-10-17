local checks = require('checks')
local errors = require('errors')
local math = require('math')
local net_box = require('net.box')

local ClientError = errors.new_class('ClientError', {capture_stack = false})

local function read()
    return {
        f = 'read',
        v = nil,
    }
end

local function transfer()
    return {
        f = 'write',
        v = math.random(1, 10),
    }
end

local space_name = 'bank_space'
local addr = '127.0.0.1:3301' -- FIXME

local function open(self)
    checks('table')

    local conn = net_box.connect(addr)
    if conn:ping() ~= true then
        return nil, ClientError:new('Failed connect to %s', addr)
    end
    assert(conn:wait_connected(0.5) == true)
    assert(conn:is_connected() == true)
    rawset(self, 'conn', conn)

    return true
end

local function setup(self)
    checks('table')

    local conn = rawget(self, 'conn')
    if conn:ping() ~= true then
        return nil, ClientError
    end

    --[[
    conn.schema.create_space(space_name)
    conn.space.space_name:format({
        {
            name='id', type='number'
        },
        {
            name='value', type='string'
        },
    })
    conn.space.space_name:create_index('pk')

           (info (str "Creating table " table-name))
           (j/execute! conn [(str "CREATE TABLE IF NOT EXISTS " table-name
                             "(id INT NOT NULL PRIMARY KEY,
                             balance INT NOT NULL)")])
           (j/execute! conn [(str "SELECT LUA('return box.space."
                                  (clojure.string/upper-case table-name)
                                  ":alter{ is_sync = true } or 1')")])
           (doseq [a (:accounts test)]
               (info "Populating account")
               (sql/insert! conn table-name {:id      a
                                             :balance (if (= a (first (:accounts test)))
                                                       (:total-amount test)
                                                       0)})))
    ]]

    return true
end

local function invoke(self, op)
    checks('table', {
        f = 'string',
        v = '?',
    })

    local conn = rawget(self, 'conn')
    if conn:ping() ~= true then
        return nil, ClientError
    end

    local tuple_id = 1
    local space = conn.space[space_name]
    assert(space ~= nil)
    local tuple_value
    local state
    if op.f == 'transfer' then
        tuple_value = space:replace({tuple_id, op.v}, {timeout = 0.05})
        tuple_value = tuple_value.value
        state = true
        --[[
        :transfer
        (let [{:keys [from to amount]} (:value op)
              con (cl/open (first (db/primaries test)) test)
              table (clojure.string/upper-case table-name)
              r (-> con
                    (sql/query [(str "SELECT _WITHDRAW('" table "'," from "," to "," amount ")")])
                    first
                    :COLUMN_1)]
          (if (false? r)
                (assoc op :type :fail, :value {:from from :to to :amount amount})
                (assoc op :type :ok))))))
        ]]
    elseif op.f == 'read' then
        tuple_value = space:get(tuple_id, {timeout = 0.05})
        if tuple_value ~= nil then
            tuple_value = tuple_value.value
        end
        state = true
    else
        return nil, ClientError:new('Unknown operation (%s)', op.f)
    end

    return {
        v = tuple_value,
        f = op.f,
        state = state,
    }
end

local function teardown(self)
    checks('table')

    local conn = rawget(self, 'conn')
    if conn:ping() ~= true then
        return nil, ClientError:new('Failed connect to %s', addr)
    end
    -- FIXME: conn.space.register_space:drop()

    return true
end

local function close(self)
    checks('table')

    local conn = rawget(self, 'conn')
    if conn:ping() ~= true then
        return nil, ClientError:new('Failed connect to %s', addr)
    end
    conn:close()

    return true
end

local client_mt = {
    __type = '<client>',
    __tostring = function(self)
        return '<client>'
    end,
    __index = {
        open = open,
        setup = setup,
        invoke = invoke,
        teardown = teardown,
        close = close,
    },
    __newindex = function()
        error('Client object is immutable.', 2)
    end
}

local function new()
    return setmetatable({
        conn = box.NULL,
    }, client_mt)
end

return {
    new = new,
    ops = {
       read = read,
       transfer = transfer,
    }
}
