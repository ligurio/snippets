# PostgreSQL microbenchmarks

## How to use:

- edit postgresql.conf:
```
shared_buffers=256MB
wal_buffers=16MB
checkpoint_segments=16
```
- ```$ pip install pytest pytest-benchmark pygal pygaljs```
- ```$ pytest tests/test_perf.py --benchmark-autosave --benchmark-compare-fail=mean:0.001 --benchmark-histogram```


## Resources

- [pgsql-performance@](https://www.postgresql.org/list/pgsql-performance/)
- [pgsql-hackers@](https://www.postgresql.org/list/pgsql-hackers/)
- [pgbench-tools](https://github.com/gregs1104/pgbench-tools)
- [SQLite speed mesaurements](https://www.sqlite.org/speed.html)
- [json_api_bench](https://github.com/JackC/json_api_bench)
- NoSQL benchmarks: [microb](https://github.com/tarantool/microb/) and [cbench](https://github.com/tarantool/cbench)
- [Database Hardware Benchmarking](https://www.pgcon.org/2009/schedule/events/152.en.html)
- [MySQL performance testing](https://dev.mysql.com/doc/mysql-development-cycle/en/performance-testing.html)
- [PostgreSQL Performance Farm](https://git.postgresql.org/gitweb/?p=pgperffarm.git;a=summary)
- https://www.postgresql.org/docs/current/static/pgbench.html
- https://www.postgresql.org/docs/current/static/performance-tips.html
- https://wiki.postgresql.org/wiki/Performance_Optimization
- https://wiki.postgresql.org/wiki/Regression_Testing_with_pgbench

Copyright (c) 2017, Sergey Bronnikov sergeyb@bronevichok.ru
