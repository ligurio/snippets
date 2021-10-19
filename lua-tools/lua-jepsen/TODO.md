### TODO

- MVP:
    - return table with number of operations from cliens
    - pass random node to clien_wrap.start()
    - implement gen.cycle()
    - implement gen.take()
    - implement gen.iter()
    - 1Mops with empty client
    - implement a bank checker
    - fix Tarantool space setup in a Client
    - test fixture with cluster
    - handle timeouts and errors in operations
- add more generators
    - time_out: run workload with timeout
    - mix()
    - gen/time-limit 30
    - sleep
    - logging
    - stagger, take total rates, rather than the rate per thread.
    - To wait for the write to complete first:
      (gen/phases {:f :write, :value 3} {:f :read})
    - gen/each-thread [{:f :inc} {:f :read}]
    - Reserve 5 threads for reads, 10 threads for increments, and the remaining threads reset a counter.
      (gen/reserve 5 (repeat {:f :read}) 10 (repeat {:f :inc}) (repeat {:f :reset}))
    - support shared state for generators
    - Contexts
        :time           The current Jepsen linear time, in nanoseconds
        :free-threads   A collection of idle threads which could perform work
        :workers        A map of thread identifiers to process identifiers
- checkers
    - https://github.com/rystsov/fast-jepsen/blob/master/jepsen/src/src/mongo_http/fchecker.clj
    - https://vectorized.io/blog/validating-consistency/
    - http://rystsov.info/2017/07/16/linearizability-testing.html
    - produce an [Elle-compatible test log](https://github.com/anishathalye/porcupine/tree/master/test_data/jepsen)
    - impement code to run third-party checkers (at least elle)
    - elle-cli? https://github.com/jepsen-io/elle/issues/13
- add tutorial https://github.com/jepsen-io/jepsen/blob/main/doc/tutorial/index.md
- nemeses support
        - signals to processes
        - filesystem
- integration test with etcd
- add remote setup using ssh:
    - https://github.com/hyee/dbcli/blob/master/lua/ssh.lua
    - https://github.com/fnordpipe/lua-ssh
- pseudo-random generator, see https://github.com/tarantool/p2phub/blob/60a511ac80f376842ac4187bc4decc498b6abf59/src/lib/hashing.lua#L46-L65
- support Lua lanes (https://lualanes.github.io/lanes/)
- remove tarantool as dependence:
    - use Lua coroutines
    - logging https://github.com/lunarmodules/lualogging
    - pure tarantool connector on lua https://github.com/tarantool/tarantool-lua
    - (etcd) http client https://daurnimator.github.io/lua-http/0.2/
    - (etcd) json lib https://github.com/rxi/json.lua
