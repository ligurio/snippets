# -*- coding: utf-8 -*-

import platform
import psycopg2
import pytest
import random
import subprocess


CONN_STRING = "host='localhost' user='postgres'"
PGDATA = "/Users/sergeyb/Downloads/pgdata/"
SCALE = 1000
SEED = 100000

def cleanup():
    conn = psycopg2.connect(CONN_STRING)
    cursor = conn.cursor()
    cursor.execute("BEGIN")
    cursor.execute("DROP TABLE IF EXISTS t1")
    cursor.execute("DROP TABLE IF EXISTS t2")
    cursor.close()
    conn.commit()
    conn.close()

def setup():
    random.seed(SEED)
    conn = psycopg2.connect(CONN_STRING)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS t1(a INTEGER, b INTEGER, c VARCHAR(100))")
    cursor.execute("CREATE TABLE IF NOT EXISTS t2(a INTEGER, b INTEGER, c VARCHAR(100))")
    for i in range(1, SCALE):
        a = random.randint(1, 25000)
        b = random.randint(1, 25000)
        cursor.execute("INSERT INTO t1 (a, b) VALUES (%s, %s)" % (a, b))
        cursor.execute("INSERT INTO t2 (a, b) VALUES (%s, %s)" % (b, a))
    cursor.close()
    conn.commit()
    conn.close()


@pytest.fixture
def make_table(request):

    cleanup()
    setup()
    request.addfinalizer(cleanup)


def reset_cache():
    """
    "There is no way to bypass or flush the database's cache.
    All you can do to clear it is restart the server." – Greg Smith
    """

    subprocess.check_output("sync")
    cmd = ["pg_ctl", "-w", "-D", PGDATA, "stop"]
    subprocess.call(cmd)
    if platform.system() == "Linux":
        # https://linux-mm.org/Drop_Caches
        with open("/proc/sys/vm/drop_caches", 'r') as file:
            file.write('3')
    cmd = ["pg_ctl", "-w", "-D", PGDATA, "start"]
    return subprocess.call(cmd)


def isdebug():
    """
    One critical thing to be aware of is that many testing builds of
    PostgreSQL, including the pre-release RPM versions, are compiled with
    assertion code turned on. Assertions help find bugs, but they will
    substantially slow down performance tests, particularly if you've increased
    shared_buffers to a large value.
    """

    conn = psycopg2.connect(CONN_STRING)
    cursor = conn.cursor()
    cursor.execute("SHOW debug_assertions")
    debug = cursor.fetchone()
    if debug is not None:
        debug = debug[0]
    cursor.close()
    conn.close()

    return debug


@pytest.fixture
def postgres(request):

    reset_cache()

    if isdebug() == 'on':
        pytest.fail("debug is enabled")

    conn = psycopg2.connect(CONN_STRING)
    cursor = conn.cursor()

    def postgres_teardown():
        conn.close()
        cursor.close()

    request.addfinalizer(postgres_teardown)
    return cursor


def test_snapshot(benchmark, postgres):
    @benchmark
    def target():
        postgres.execute("SELECT 1")


def test_increment_xid(benchmark, postgres):
    @benchmark
    def target():
        postgres.execute("SELECT txid_current()")


def test_read_relation(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("SELECT COUNT(*) FROM t1")


@pytest.mark.sqlite
def test_1k_inserts(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("BEGIN")
        for i in range(0, 1000):
            postgres.execute("INSERT INTO t1 (a, b) VALUES (%s, %s)" % (i, 1000 - i))
        postgres.execute("COMMIT")


@pytest.mark.sqlite
def test_25k_inserts_at_once(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("BEGIN")
        for i in range(0, 25000):
            postgres.execute("INSERT INTO t1 (a, b) VALUES (%s, %s)" % (i, 250000 - i))
        postgres.execute("COMMIT")


@pytest.mark.sqlite
def test_25k_inserts_at_once_indexed(benchmark, make_table, postgres):
    postgres.execute("CREATE INDEX i3a ON t1(a);")
    postgres.execute("CREATE INDEX i3b ON t1(b);")
    @benchmark
    def target():
        postgres.execute("BEGIN")
        for i in range(0, 25000):
            postgres.execute("INSERT INTO t1 VALUES (%s, %s)" % (i, 25000 - i))
        postgres.execute("COMMIT")


@pytest.mark.sqlite
def test_100_selects_wo_index(benchmark, make_table, postgres):
    @benchmark
    def target():
        for i in xrange(0, 100, 10000):
            postgres.execute("SELECT count(*), avg(b) FROM t1 WHERE b>=%s AND b<%s;" % (i, 1000 + i))


@pytest.mark.skip(reason="not implemented")
@pytest.mark.sqlite
def test_100_selects_on_string_comparison(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("BEGIN")
        # SELECT count(*), avg(b) FROM t2 WHERE c LIKE '%one%';
        # SELECT count(*), avg(b) FROM t2 WHERE c LIKE '%two%';
        # ... 96 lines omitted
        # SELECT count(*), avg(b) FROM t2 WHERE c LIKE '%ninety nine%';
        # SELECT count(*), avg(b) FROM t2 WHERE c LIKE '%one hundred%';
        for i in xrange(100, 100, 10000):
            postgres.execute("SELECT count(*), avg(b) FROM t2 WHERE c LIKE '%one%';")
        postgres.execute("COMMIT")


@pytest.mark.sqlite
def test_5k_selects_with_index(benchmark, make_table, postgres):
    postgres.execute("CREATE INDEX i2a ON t1(a);")
    postgres.execute("CREATE INDEX i2b ON t1(b);")
    @benchmark
    def target():
        for i in xrange(0, 100, 500000):
            postgres.execute("SELECT count(*), avg(b) FROM t1 WHERE b>=%s AND b<%s;" % (i, 100 + i))


@pytest.mark.sqlite
def test_10k_updates_wo_index(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("BEGIN")
        for i in xrange(0, 10, 100000):
            postgres.execute("UPDATE t1 SET b=b*2 WHERE a>=%s AND a<%s;" % (i, 10 + i))
        postgres.execute("COMMIT")


@pytest.mark.sqlite
def test_25k_updates_with_index(benchmark, make_table, postgres):
    postgres.execute("CREATE INDEX i2a ON t1(a);")
    postgres.execute("CREATE INDEX i2b ON t1(b);")
    @benchmark
    def target():
        postgres.execute("BEGIN")
        for a in xrange(1, 1, 25000):
            b = random.randint(1, 500000)
            postgres.execute("UPDATE t1 SET b=%s WHERE a=%s;" % (b, a))
        postgres.execute("COMMIT")


@pytest.mark.skip(reason="not implemented")
@pytest.mark.sqlite
def test_25k_text_updates_with_index(benchmark, make_table, postgres):
    postgres.execute("CREATE INDEX i2a ON t2(a);")
    postgres.execute("CREATE INDEX i2b ON t2(b);")
    @benchmark
    def target():
        postgres.execute("BEGIN")
        for a in xrange(1, 1, 25000):
            c = ""
            # UPDATE t2 SET c='one hundred forty eight thousand three hundred eighty two' WHERE a=1;
            postgres.execute("UPDATE t2 SET c='%s' WHERE a=1;" % (c, a))
        postgres.execute("COMMIT")


@pytest.mark.skip(reason="not implemented")
@pytest.mark.sqlite
def test_inserts_from_select(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("BEGIN")
        postgres.execute("INSERT INTO t1 SELECT b,a,c FROM t2;")
        postgres.execute("INSERT INTO t2 SELECT b,a,c FROM t1;")
        postgres.execute("COMMIT")


@pytest.mark.skip(reason="not implemented")
@pytest.mark.sqlite
def test_delete_wo_index(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("BEGIN")
        postgres.execute("DELETE FROM t2 WHERE c LIKE '%fifty%';")
        postgres.execute("COMMIT")


@pytest.mark.sqlite
def test_delete_with_index(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("BEGIN")
        postgres.execute("DELETE FROM t1 WHERE a>10 AND a<20000;")
        postgres.execute("COMMIT")


@pytest.mark.sqlite
def test_big_insert_after_big_delete(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("BEGIN")
        postgres.execute("DELETE FROM t1 WHERE a>10 AND a<20000;")
        postgres.execute("COMMIT")

        postgres.execute("BEGIN")
        postgres.execute("INSERT INTO t1 SELECT * FROM t2;")
        postgres.execute("COMMIT")


@pytest.mark.skip(reason="not implemented")
@pytest.mark.sqlite
def test_big_delete_followed_by_many_small_inserts(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("BEGIN")
        postgres.execute("DELETE FROM t1;")
        for i in xrange(1, 1, 12000):
            postgres.execute("INSERT INTO t1 VALUES(%s,10719,'ten thousand seven hundred nineteen');" % i)
        postgres.execute("COMMIT")


@pytest.mark.skip(reason="not implemented")
@pytest.mark.sqlite
def test_drop_table(benchmark, postgres):
    def target():
        postgres.execute("DROP TABLE t1;")
        postgres.execute("DROP TABLE t2;")
    benchmark.pedantic(target, setup=setup, rounds=100)


def test_copy(benchmark, postgres):
    @benchmark
    def target():
        cmd = ["pgbench", "-i", "-n", "-s", "100"]
        subprocess.check_output(cmd)


@pytest.mark.skip(reason="not implemented")
def test_PLPgSQL(benchmark, postgres):
    @benchmark
    def target():
        # https://www.postgresql.org/message-id/51EE54BE.3090606@gmail.com
        pass


@pytest.fixture
def drop_index(request):

    conn = psycopg2.connect(CONN_STRING)
    cursor = conn.cursor()
    cursor.execute("SELECT indexname FROM pg_indexes WHERE tablename='t1'")
    indexes = cursor.fetchall()
    for i in indexes:
        cursor.execute("DROP INDEX %s" % i)
    cursor.commit()
    cursor.close()
    conn.close()


@pytest.mark.skip(reason="not implemented")
# iterations: 1000, 5000, 10000, 50000, 1000000, 500000
@pytest.mark.parametrize("index", [("btree"),
                                    ("hash"),
                                    ("brin"),
                                    ("gin"),
                                    ("spgist"),
                                    ("gist")])
def test_create_index(benchmark, make_table, postgres, index, drop_index):
    if index == "btree":
        col = "a"
    elif index == "hash":
        col = "a"
    elif index == "brin":
        col = "a"
    elif index == "gin":
        col = "a"
    elif index == "spgist":
        col = "a"
    elif index == "gist":
        col = "a"
    @drop_index
    @benchmark
    def target():
        #SQL = "CREATE INDEX %s_idx ON t1 USING %s(%s);" % (index, index, col)
        #postgres.execute(SQL)
        pass


@pytest.mark.skip(reason="not implemented")
# https://www.postgresql.org/docs/current/static/runtime-config-query.html
# measure am performance (1000, 5000, 10000, 50000, 1000000, 500000):
@pytest.mark.parametrize("method", [("enable_bitmapscan"),
                                ("enable_hashagg"),
                                ("enable_hashjoin"),
                                ("enable_indexscan"),
                                ("enable_indexonlyscan"),
                                ("enable_material"),
                                ("enable_mergejoin"),
                                ("enable_nestloop"),
                                ("enable_seqscan"),
                                ("enable_sort"),
                                ("enable_tidscan")])
def test_access(benchmark, make_table, postgres, method):
    @benchmark
    def target():
        postgres.execute("ANALYSE t1;")
        # SET enable_indexonlyscan = off;
        postgres.execute("EXPLAIN ANALYSE SELECT count(*) FROM t1 WHERE a <= 10000;")


# http://sigaev.ru/git/gitweb.cgi?p=ftsbench.git;a=summary
@pytest.mark.skip(reason="not implemented")
def test_ftsbench(benchmark, postgres):
    @benchmark
    def target():

        pass


@pytest.mark.skip(reason="not implemented")
def test_fts_search(benchmark, postgres):
    """
    Time of FTS searching and sorting (and separately for phrase search)
    """
    @benchmark
    def target():

        pass


def test_readonly_queries(benchmark, postgres):
    cmd = ["pgbench", "-i", "-n", "-s", "100"]
    subprocess.check_output(cmd)
    @benchmark
    def target():
        cmd = ["pgbench", "-S", "-t", "100", "-c", "10", "-P", "5"]
        subprocess.check_output(cmd)


def test_cpu_test(benchmark, postgres):
    @benchmark
    def target():
        postgres.execute("SELECT SUM(generate_series) FROM generate_series(1, 1000000);")


def test_quick_insert_plan(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("INSERT INTO t1 (a) VALUES (GENERATE_SERIES(1, 100000));")
        postgres.execute("EXPLAIN ANALYZE SELECT COUNT(*) FROM t1;")


def test_sort(benchmark, make_table, postgres):
    @benchmark
    def target():
        postgres.execute("SELECT * FROM t1 ORDER BY a;")


@pytest.mark.skip(reason="not implemented")
def test_hash(benchmark, postgres):
    """
    Performance of hash (single and many threads)
    """
    @benchmark
    def target():

        pass
