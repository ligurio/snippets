### TODO

- run workload with timeout
- add more generators, see http://jepsen-io.github.io/jepsen/jepsen.generator.html
- produce an [Elle-compatible test log](https://github.com/anishathalye/porcupine/tree/master/test_data/jepsen)
- impement code to run checkers
- add tutorial https://github.com/jepsen-io/jepsen/blob/main/doc/tutorial/index.md
- nemeses support (process signals, filesystem, time)
- handle timeouts in operations
- integration test with etcd
- integration test with simple socket server
- support shared state for generators
- https://aphyr.com/posts/316-jepsen-etcd-and-consul
- add remote setup using ssh:
    - https://github.com/hyee/dbcli/blob/master/lua/ssh.lua
    - https://github.com/fnordpipe/lua-ssh
- describe Lua advantages:
> Pure generators perform all generator-related computation on a single thread,
> and create additional garbage due to their pure functional approach. However,
> realistic generator tests yield rates over 20,000 operations/sec, which seems
> more than sufficient for Jepsen’s purposes.
[Source](http://jepsen-io.github.io/jepsen/jepsen.generator.html)
- pseudo-random generator, see https://github.com/tarantool/p2phub/blob/60a511ac80f376842ac4187bc4decc498b6abf59/src/lib/hashing.lua#L46-L65
- support Lua lanes (https://lualanes.github.io/lanes/)
- support Lua coroutines
