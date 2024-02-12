checkers = { }

local function __FILE__() return debug.getinfo(3, 'S').source end
local function __LINE__() return debug.getinfo(3, 'l').currentline end
local function __FUNC__() return debug.getinfo(3, 'n').name or '' end

local function check_one(expected, val)
    if type(val)==expected then return true end
    local mt = getmetatable(val)
    if mt and mt.__type==expected then return true end
    local f = checkers[expected]
    if f and f(val) then return true end
    return false
end

local function check_many(_, expected, val)
    if expected=='?' then return true
    elseif expected=='!' then return (val~=nil)
    elseif type(expected) ~= 'string' then
        error 'strings expected by checks()'
    elseif val==nil and expected :sub(1,1) == '?' then return true end
    for one in expected :gmatch "[^|?]+" do
        if check_one(one, val) then return true end
    end
    return false
end

local function checks(...)
    for i, arg in ipairs{...} do
        local name, val = debug.getlocal(2, i)
        local success = check_many(name, arg, val)
        if not success then
            local fname = debug.getinfo(2, 'n').name
            local fmt = "bad argument #%d to '%s' (%s expected, got %s)"
            local msg = string.format(fmt, i, fname or "?", arg, type(val))
            error(msg, 3)
        end
    end
end

return checks
