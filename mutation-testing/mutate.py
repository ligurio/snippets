#!/usr/local/bin/python

import subprocess
import os

sources = { '../sources/libs/kos/coresrv/entity/entity_api.c': 'make knentitytests/qtest',
            '../sources/libs/kos/coresrv/sl/sl-static.c': 'make knsltests/qtest',
            '../sources/libs/kos/coresrv/sl/sl_api.c': 'make knsltests/qtest',
            '../sources/libs/kos/coresrv/task/task_api.c': 'make kntasktests/qtest',
            '../sources/libs/kos/coresrv/thread/thread_api.c': 'make knthreadtests/qtest',
            '../sources/libs/kos/coresrv/time/time_api.c': 'make kntimetests/qtest',
            '../sources/libs/kos/coresrv/vlog/vlog_api.c': 'make knvlogtests/qtest' }

for source, test_cmd in sources.items():
    print "Source file: %s, tests %s" % (source, test_cmd)
    mutation_cmd = "cp tmp_mutant.c %s; python check_status.py '%s'" % (source, test_cmd)
    cmd = ["mutate", source, "--cmd", mutation_cmd, "--mutantDir", "task_api"]
    output = subprocess.check_output(cmd)
    log = os.path.basename(source)
    with open(log, 'w') as l:
        l.write(output)