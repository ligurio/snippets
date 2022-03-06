```lua
box.cfg{
    work_dir = "work_dir",
}

box.schema.user.grant('guest', 'execute', 'universe', nil, { if_not_exists = true })

local s = box.schema.space.create('testDatetime', {
    id = 524,
    if_not_exists = true,
})
s:create_index('primary', {
    type = 'TREE',
    parts = {
        {
            field = 1,
            type = 'datetime',
        },
    },
    if_not_exists = true
})
s:truncate()

box.schema.user.grant('guest', 'read,write', 'space', 'testDatetime', { if_not_exists = true })

-- Set listen only when every other thing is configured.
box.cfg{
    listen = 3013
}

require('console').start()
```

1. Install AFL https://afl-1.readthedocs.io/en/latest/INSTALL.html#install
2. Build Tarantool with AFL
	CC=~/sources/AFLplusplus/afl-cc CXX=~/sources/AFLplusplus/afl-g++ cmake -DENABLE_GCOV=ON ..
	make -j
See quickstart guide https://afl-1.readthedocs.io/en/latest/quick_start.html
3. tarantool config.lua && jq -M .payload.hex < dump_datetime | sed 's/"//g' | xxd -r -p | nc localhost 3013

```sh
$ cat dump_datetime 
{"headers": {"ip": {"id": 3095, "src": "127.0.0.1", "dst": "127.0.0.1"}, "tcp": {"sport": 47178, "dport": 3013, "seq": 2965179756, "ack": 1159921438, "window": 64}}, "payload": {"hex": "ce 00 00 00 18 82 00 02 01 ce 00 00 00 03 82 10 cd 02 0c 21 91 c7 05 04 ce 43 b9 40 e5", "iproto": [{"header": {"REQUEST_ID": 3, "COMMAND": "INSERT"}, "body": {"SPACE_ID": 524, "TUPLE": [[4, "ce 43 b9 40 e5"]]}}]}}
$ mkdir testcase_dir
$ cp dump_datetime testcase_dir/
$ tarantool config.lua
$ jq -M .payload.hex < dump_datetime | sed 's/"//g' | xxd -r -p | nc localhost 3013
```
