-- Function implements a UPSERT operation, which takes a key and value and sets
-- the key to the value if key exists or insert new key with that value.
local function upsert(conn, space_name, tuple_id, value)
    local space = conn.space[space_name]
    space:upsert({tuple_id, value}, {{'=', 2, value}})

    return true
end

return {
    upsert = upsert,
}
