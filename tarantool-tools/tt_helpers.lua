local function dict_keys(t)
    assert(next(t) ~= nil)
    local keys = {}
    for k, _ in pairs(t) do
        table.insert(keys, k)
    end
	return keys
end

local function random_elem(t)
    assert(type(t) == 'table')
    assert(next(t) ~= nil)

    local n = #t
    local idx = math.random(1, n)
    return t[idx]
end

local charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

local function random_string(length)
  local length = length or 1
  assert(length > 0)
  return random_string(length - 1) .. charset:sub(math.random(1, #charset), 1)
end

return {
    dict_keys = dict_keys,
	random_elem = random_elem,
	random_string = random_string,
}
