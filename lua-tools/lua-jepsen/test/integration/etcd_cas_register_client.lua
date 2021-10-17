local checks = require('checks')
local fun = require('fun')
local math = require('math')

math.randomseed(os.time())

local function r()
    return {
        type = 'invoke',
        f = 'read',
        v = nil,
    }
end

local function w()
    return {
        type = 'invoke',
        f = 'write',
        v = math.random(1, 10),
    }
end

local function cas()
    return {
        type = 'invoke',
        f = 'cas',
        v = {
            math.random(1, 10), -- old value
            math.random(1, 10), -- new value
        }
    }
end

local client = {}

function client.open(test)
    checks('table')
    assert(test)
end

function client.setup(test)
    checks('table')

    assert(test)
end

function client.invoke(test)
    checks('table')

    assert(test)
end

function client.teardown(test)
    checks('table')

    assert(test)
end

function client.close(test)
    checks('table')

    assert(test)
end

return {
    client = client,
    generator = fun.rands(0, 3):map(function(x)
                                        return (x == 0 and r()) or
                                               (x == 1 and w()) or
                                               (x == 2 and cas())
                                    end):take(50),
    checker = nil,
}
