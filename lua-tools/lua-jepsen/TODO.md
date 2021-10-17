### TODO

- убрать лишние функции в jepsen/gen.lua
- не использовать checks() в рантайме?
+ associate connection with Client
- fix Tarantool space setup in a Client
- execute setup() on every instance
- run workload with timeout
- test fixture with cluster
- add more generators, see http://jepsen-io.github.io/jepsen/jepsen.generator.html
    - support shared state for generators
    - randomize operations (mix()?)
    - luafun's generators for chaining
    - sleep
    - logging
    - stagger, take total rates, rather than the rate per thread.
    - To wait for the write to complete first:
      (gen/phases {:f :write, :value 3} {:f :read})
    - gen/each-thread [{:f :inc} {:f :read}]
    - Reserve 5 threads for reads, 10 threads for increments, and the remaining threads reset a counter.
      (gen/reserve 5 (repeat {:f :read}) 10 (repeat {:f :inc}) (repeat {:f :reset}))
    - gen/time-limit 30
    - Contexts
        :time           The current Jepsen linear time, in nanoseconds
        :free-threads   A collection of idle threads which could perform work
        :workers        A map of thread identifiers to process identifiers
- checkers
    - implement a bank checker
    - produce an [Elle-compatible test log](https://github.com/anishathalye/porcupine/tree/master/test_data/jepsen)
    - impement code to run third-party checkers (at least elle)
    - elle-cli?
    - lein uberjar https://github.com/jepsen-io/elle/issues/13
- add tutorial https://github.com/jepsen-io/jepsen/blob/main/doc/tutorial/index.md
- nemeses support
        - signals to processes
        - filesystem
- handle timeouts in operations
- integration test with etcd
- integration test with simple socket server https://www.tarantool.io/en/doc/latest/reference/reference_lua/socket/
- https://aphyr.com/posts/316-jepsen-etcd-and-consul
- add remote setup using ssh:
    - https://github.com/hyee/dbcli/blob/master/lua/ssh.lua
    - https://github.com/fnordpipe/lua-ssh
- pseudo-random generator, see https://github.com/tarantool/p2phub/blob/60a511ac80f376842ac4187bc4decc498b6abf59/src/lib/hashing.lua#L46-L65
- support Lua lanes (https://lualanes.github.io/lanes/)
- support Lua coroutines
