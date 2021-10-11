### TODO

- timeout in operations
- elle-compatible test log https://github.com/anishathalye/porcupine/tree/master/test_data/jepsen
- add nemeses support
- generators http://jepsen-io.github.io/jepsen/jepsen.generator.html
- https://gist.github.com/sergos/c2dae39bf1ac47519356de23601ea7f4
- https://aphyr.com/posts/316-jepsen-etcd-and-consul
- https://github.com/tarantool/p2phub/blob/60a511ac80f376842ac4187bc4decc498b6abf59/src/lib/hashing.lua#L46-L65
- tutorial https://github.com/jepsen-io/jepsen/blob/main/doc/tutorial/index.md
- remote instances via ssh
    - https://github.com/hyee/dbcli/blob/master/lua/ssh.lua
    - https://github.com/fnordpipe/lua-ssh

> Pure generators perform all generator-related computation on a single thread,
> and create additional garbage due to their pure functional approach. However,
> realistic generator tests yield rates over 20,000 operations/sec, which seems
> more than sufficient for Jepsen’s purposes.
http://jepsen-io.github.io/jepsen/jepsen.generator.html
