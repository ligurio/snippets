-- queue implementation in Lua
-- https://www.lua.org/pil/11.4.html
--
-- Example:
-- queue = require('queue').new()
-- queue.pushright(1)
-- queue.pushleft(2)
-- queue.pushright(3)
-- queue.popright(3)
-- queue.pprint()

local function pushleft(self, value)
    print('last', self._last)
    print('first', self._last)

    self._first = self._first - 1
    self._queue[self._first] = value
end

local function pushright(self, value)
    print('last', self._last)
    print('first', self._last)
    self._last = self._last + 1
    self._queue[self._last] = value
end

local function popleft(self)
    print('last', self._last)
    print('first', self._last)

    if self._first > self._last then
    	error("list is empty")
    end
    local value = self._queue[self._first]
    self._queue[self._first] = nil
    self._first = self._first + 1
    return value
end

local function popright(self)
    print('last', self._last)
    print('first', self._last)

    if self._first > self._last then
        error("list is empty")
    end
    local value = self._queue[self._last]
    _queue[self._last] = nil
    self._last = self._last - 1
    return value
end

local function pprint(self)
    for k, v in pairs(self._queue) do
        print(k, v)
    end
end

mt = {
    __index = {
        pushright = pushright,
        pushleft = pushleft,
        popright = popright,
        popleft = popleft,
        pprint = pprint,
    },
}

local function new()
    return setmetatable({
        _queue = {},
        _first = 0,
        _last = -1
    }, mt)
end


return {
    new = new
}
