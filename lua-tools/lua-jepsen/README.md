## lua-jepsen

<!--
- Testing distributed systems is difficult.
- Clojure is not a popular language in software industry.
- Lua is a simple programming language and easy to learn.
- Tarantool has a native Lua support and Clojure looks foreign for it.
- There is a [Jecci](https://github.com/michaelzenz/jecci) that aims to
  simplify building Jepsen tests.
-->

### Prerequisites

- [Tarantool](https://www.tarantool.io/en/) as a Lua interpreter (built-in
  json, http, fiber and luafun modules).
- [checks](https://github.com/tarantool/checks) - easy, terse, readable and
  fast function arguments type checking.
- [errors](https://github.com/tarantool/errors) - error objects with stack
  trace support.
- (optional) [luafun](https://luafun.github.io/basic.html) - Lua functional
  library.
- (optional) [luasql](https://keplerproject.github.io/luasql/manual.html) - is
  a simple interface from Lua to a number of database management systems.
- (optional) [luatest](https://github.com/tarantool/luatest) or any other
  unit-testing framework.
- (optional) [unreliablefs](https://github.com/ligurio/unreliablefs) - a
  FUSE-based fault injection filesystem.
- (optional) Jepsen-compatible consistency checker: Elle (recommended),
  Knossos, Porcoupine.

### How-to use

Download library:
```sh
$ luarocks install lua-jepsen
```

Run tests:
```sh
$ export ETCD_PATH=$HOME/.local/bin
$ luatest -v test/
```

### Possible workloads

- `append` checks for dependency cycles in append/read transactions.
- `bank` concurrent transfers between rows of a shared table.
- `bank-multitable` multi-table variant of the bank test.
- `long-fork` distinguishes between parallel snapshot isolation and standard SI.
- `monotonic` looks for contradictory orders over increment-only registers.
- `register` concurrent atomic updates to a shared register.
- `sequential` looks for serializable yet non-sequential orders on independent
  registers.
- `set` concurrent unique appends to a single table.
- `set-cas` appends elements via compare-and-set to a single row.
- `table` checks for a race condition in table creation.
- `txn-cycle` looks for write-read dependency cycles over read-write registers.

<!--
https://github.com/jepsen-io/jepsen/blob/7f3d0b1ca20b27681f3af10124a8b2d2d98c8e18/tidb/src/tidb/monotonic.clj#L37-L87
https://github.com/fauna/jepsen/blob/b5c3b20d27166ca87796b48077ac17feec2937f9/src/jepsen/faunadb/monotonic.clj
-->

<!--
- Multimonotonic

Similar to the monotonic test, this test takes an increment-only
register and looks for cases where reads flow backwards. Unlike the
monotonic test, we try to maximize performance (and our chances to
observe nonmonotonicity) by sacrificing some generality: all updates to
a given register happen in a single worker, and are performed as blind
writes to avoid triggering OCC read locks which lower throughput.

https://github.com/fauna/jepsen/blob/b5c3b20d27166ca87796b48077ac17feec2937f9/src/jepsen/faunadb/multimonotonic.clj

- Sequential

Sequential: in one process, perform two write transactions (`write_1` then
`write_2`), concurrently read in the reverse order.

Claim: no instances where `write_2` is present before `write_1` should be
discovered. Required for: sequential Consistency.

To do this, we establish a set of registers, each comprised of a key and
a value. On each register separately, we perform a series of increment
operations, mixed with reads of that register. Since our transactions
only interact with single keys, snapshot isolation implies
serializability. Since the value of a register can only increase over
time, we expect that for any given process, and for any given register
read by that process, the value of that register should monotonically
increase.

Sequential consistency requires that the orders of operations observed by each
individual client be consistent with one another. We evaluate sequential
consistency by having one process perform two transactions, each inserting a
different key, and, concurrently, reading those keys in the reverse order using
a second process:

```
T1: w(x, 1)
T2: w(y, 1)
T3: r(y)
T4: r(x)
```

A serializable system could allow x and y to be inserted in either order, and
likewise, could evaluate the reads at any point in time: reads could see
neither, only x, only y, or both. A sequentially consistent system, however,
can never observe y alone, since the same process inserted x prior to y.

- Bank

Test simulates a set of bank accounts, one per row, and transfers money
between them at random, ensuring that no account goes negative. Under
snapshot isolation, one can prove that transfers must serialize, and the
sum of all accounts is conserved. Meanwhile, read transactions select
the current balance of all accounts. Snapshot isolation ensures those
reads see a consistent snapshot, which implies the sum of accounts in
any read is constant as well.

The bank test stresses several invariants provided by snapshot
isolation. We construct a set of bank accounts, each with three
attributes:

- *type*, which is always "account". We use this to query for all
  accounts.
- *key*, an integer which identifies that account.
- *amount*, the amount of money in that account.

Our test begins with a fixed amount ($100) of money in a single account,
and proceeds to randomly transfer money between accounts. Transfers
proceed by reading two random accounts by key, and writing back new
amounts for those accounts to reflect some money moving between them.
Concurrently, clients read all accounts to observe the total state of
the system.

Bank: simulated bank accounts including transfers between accounts
(using transactions).

Claim: the total of all accounts should be consistent. Required for:
snapshot isolation.

- Long fork

Long Fork: non-intersecting transactions are run concurrently.

Claim: transactions happen in some specific order for future reads.
Prohibited in: snapshot isolation (Prefix property). Allowed in:
parallel snapshot isolation.

For performance reasons, some database systems implement parallel
snapshot isolation, rather than standard snapshot isolation. Parallel
snapshot isolation allows an anomaly prevented by standard SI: a long
fork, in which non-conflicting write transactions may be visible in
incompatible orders. As an example, consider four transactions over an
empty initial state:

```
(write x 1)
(write y 1)
(read x nil) (read y 1)
(read x 1) (read y nil)
```

Here, we insert two records, x and y. In a serializable system, one
record should have been inserted before the other. However, transaction
3 observes y inserted before x, and transaction 4 observes x inserted
before y. These observations are incompatible with a total order of
inserts.

To test for this behavior, we insert a sequence of unique keys, and
concurrently query for small batches of those keys, hoping to observe a
pair of states in which the implicit order of insertion conflicts.

Long fork is an anomaly prohibited by snapshot isolation, but allowed by
the slightly weaker model parallel snapshot isolation. In a long fork,
updates to independent keys become visible to reads in a way that isn't
consistent with a total order of those updates. For instance:

```
T1: w(x, 1)
T2: w(y, 1)
T3: r(x, 1), r(y, nil)
T4: r(x, nil), r(y, 1)
```

Under snapshot isolation, T1 and T2 may execute concurrently, because
their write sets don't intersect. However, every transaction should
observe a snapshot consistent with applying those writes in some order.
Here, T3 implies T1 happened before T2, but T4 implies the opposite. We
run an n-key generalization of these transactions continuously in our
long fork test, and look for cases where some keys are updated out of
order.

In snapshot isolated systems, reads should observe a state consistent
with a total order of transactions. A long fork anomaly occurs when a
pair of reads observes contradictory orders of events on distinct
records - for instance, T1 observing record x before record y was
created, and T2 observing y before x. In the long fork test, we insert
unique rows into a table, and query small groups of those rows, looking
for cases where two reads observe incompatible orders.

https://github.com/jepsen-io/jepsen/blob/33f05048907923eae0189d29a2bec2c5e3b2641e/yugabyte/src/yugabyte/long_fork.clj#L18-L58

- Monotonic

Monotonic: a counter which increments over time.

Claim: successive reads of that value by any single client should
observe monotonically increasing transaction timestamps and values.
Required for: monotonicity.

Verifies that clients observe monotonic state and timestamps when
performing current reads, and that reads of past timestamps observe
monotonic state.

The monotonic tests verify that transaction timestamps are consistent
with logical transaction order. In a transaction, we find the maximum
value in a table, select the transaction timestamp, and then insert a
row with a value one greater than the maximum, along with the current
timestamp, the node, process, and table numbers. When sorted by
timestamp, we expect that the values inserted should monotonically
increase, so long as transaction timestamps are consistent with the
database's effective serialization order.

For our monotonic state, we'll use a register, implemented as an
instance with a single value. That register will be incremented by =inc=
calls, starting at 0.

```
={:type :invoke, :f :inc, :value nil}=
```

which returns

```
={:type :invoke, :f inc, :value [ts, v]}=
```

Meaning that we set the value to v at time ts. Meanwhile, we'll execute
reads like:

```
={:type :invoke, :f :read, :value [ts, nil]}=
```

which means we should read the register at time =ts=, returning

```
={:type :ok, :f :read, :value [ts, v]}.=
```

If the timestamp is nil, we read at the current time, and return the
timestamp we executed at.

- Append

The *append* test models the database as a collection of named lists,
and performs transactions comprised of read and append operations. A
read returns the value of a particular list, and an append adds a single
unique element to the end of a particular list. We derive ordering
dependencies between these transactions, and search for cycles in that
dependency graph to identify consistency anomalies.

https://github.com/jepsen-io/jepsen/blob/bb972671c84f054426216392d99db0792947a1d2/yugabyte/src/yugabyte/ysql/append.clj#L45-L125

- G2

G2 checks for a type of phantom anomaly prevented by serializability:
anti-dependency cycles involving predicate reads.

We can also test for the presence of anti-dependency cycles in pairs of
transactions, which should be prevented under serializability. These
cycles, termed "G2", are one of the anomalies described by Atul Adya in
his 1999 thesis on transactional consistency. It involves a cycle in the
transaction dependency graph, where one transaction overwrites a value a
different transaction has read. For instance:

```
T1: r(x), w(y)
T2: r(y), w(x)
```

could interleave like so:

```
T1: r(x)
T2: r(y)
T1: w(y)
T2: w(x)
T1: commit
T2: commit
```

This violates serializability because the value of a key could have
changed since the transaction first read it. However, G2 doesn't just
apply to individual keys - it covers predicates as well. For example, we
can take two tables...

```
    create table a (
      id    int primary key,
      key   int,
      value int);
    create table b (
      id    int primary key,
      key   int,
      value int);
```

where =id= is a globally unique identifier, and key denotes a particular
instance of a test. Our transactions select all rows for a specific key,
in either table, matching some predicate:

```
    select * from a where
      key = 5 and value % 3 = 0;
    select * from b where
      key = 5 and value % 3 = 0;
```

If we find any rows matching these queries, we abort. If there are no
matching rows, we insert (in one transaction, to a, in the other, to b),
a row which would fall under that predicate:

```
    insert into a values (123, 5, 30);
```

In a serializable history, these transactions must appear to execute
sequentially, which implies that one sees the other's insert. Therefore,
at most one of these transactions may succeed. Indeed, this seems to
hold: we have never observed a case in which both of these transactions
committed successfully. However, a closely related test, monotonic, does
reveal a serializability violation - we'll talk about that shortly.

- Register

Register: read, writes, and compare-and-swap operations on registers.

Claim: the operations should be linearizable (according to Knossos).
Required for: snapshot isolation.

- Set

Set: unique integers inserted as rows in a table.

Claim: concurrent reads should include all present values at any given
time and at any later time. Note: a stricter variant requires immediate
visibility instead of allowing stale reads.
-->

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
