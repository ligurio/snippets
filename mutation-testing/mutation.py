#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""

Step-by-step:

- build project "CPPCHECK=echo make os" to make sure there are
    no compilation problems and gather compilation strings
- create backup of a target source file
- copy target source file to a build dir
- add fake main() to a target source file
- create mutants with frama-c and target file
- find summary.csv and filter mutations on target file only
- find compilation string for a target file and unsupported options (for example "-mcmodel=large")
- copy file with mutation instead of target source file
- run tests

Requirements:

- OCaml 4.05.0+
- Frama-C (http://frama-c.com/)
- Frama-C-Mutation (https://github.com/gpetiot/Frama-C-Mutation/)

How-To Run:

$ cd build-64
$ ../scripts/mutation.py --help
$ ../scripts/mutation.py
$ ../scripts/mutation.py --sources ../os/core/io/mmio.c ../os/core/io/interrupts.c

TODO:

- cleanup on interrupt
- output in JUnit format
- detect crashes earlier (otherwise we will wait timeout == 3 min per test)
- make code more clear (create class Mutator and convert functions to its methods)
- keep summary.csv
- skip mutation when line is not covered by tests

"""

import argparse
import datetime
import glob
import csv
import logging
import os
import sys
import signal
import shutil
import json

from subprocess import PIPE, Popen, call

# os/core/{task,thread,mm,vmm,io}
# key is a path to a source file, value is a reason why we should skip it
SOURCE_FILES = { "../os/core/mm/buddy.c": "",
                 "../os/core/mm/kmalloc.c": "",
                 "../os/core/mm/pfnbase.c": "exceptions on boot",
                 "../os/core/mm/slab.c": "",
                 "../os/core/mm/stat.c": "no mutations",
                 "../os/core/mm/stpool.c": "",
                 "../os/core/task/context.c": "timeouts on test running",
                 "../os/core/task/rtl.c": "",
                 "../os/core/task/task.c": "Parsing task.c: syntax error vmspace.h:66",
                 "../os/core/thread/exception.c": "",
                 "../os/core/thread/rtl.c": "",
                 "../os/core/thread/thread.c": "Parsing thread.c: syntax error vmspace.h:66",
                 "../os/core/vmm/fault.c": "Parsing fault.c: syntax error vmspace.h:66",
                 "../os/core/vmm/vmm.c": "Parsing vmm.c: syntax error vmspace.h:66",
                 "../os/core/vmm/vmspace.c": "Parsing vmspace.c: syntax error vmspace.h:66",
                 "../os/core/io/context.c": "",
                 "../os/core/io/dma.c": "Parsing dma.c: syntax error vmspace.h:66",
                 "../os/core/io/interrupts.c": "",
                 "../os/core/io/io_irq.c": "Parsing io_irq.c: syntax error rtl_static_assert()",
                 "../os/core/io/mmio.c": "Parsing mmio.c: syntax error vmspace.h:66",
                 "../os/core/io/port.c": "Parsing port.c: syntax error vmspace.h:66",
                 "../os/core/io/resources.c": "" }


CC_BLACKLIST = [ "-mcmodel=large" ]
EXCEPTIONS = [ 'UNHANDLED COMMON EXCEPTION', 'UNHANDLED PAGE FAULT EXCEPTION' ]

FRAMAC_SUMMARY = 'summary.csv'
FRAMAC_DELIM = ','
FRAMAC_CMD = "frama-c -c11 -no-cpp-frama-c-compliant -cpp-command 'gcc -E %s' %s -main main -mut -mut-code -mut-summary-file summary.csv"
BUILD_CMD = "make -C os"
TEST_CMD = "make -C os qemutests/run"
CLEANUP_CMD = "make clean"
MAIN_FUNC_STUB = "int main() { return 0; }"
TEMPLATE = 'mutation-template.html'

FORMAT = '%(asctime)-15s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('mutation')
logging.getLogger().setLevel(logging.INFO)


def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""

    from distutils.spawn import find_executable
    return find_executable(name) is not None


def process_build_str(string, src_file):

    cc_options = ""
    for w in string.split(' '):
        if w in CC_BLACKLIST:
            logging.info("blacklisted word detected %s", w)
            continue
        if w == src_file:
            logging.info("source file path detected %s", w)
            continue
        cc_options = cc_options + ' ' + w

    return cc_options


def execute_command(cmd, env=os.environ.copy()):
    """
    Parameters:
    Return: None
    """

    cmdline = cmd.split(' ')
    logging.debug(cmdline)

    if not env:
        env = os.environ.copy()
    process = Popen(cmdline, stdout=PIPE, stderr=PIPE, env=env)
    stdoutdata = ""
    while True:
	output = process.stdout.readline()
	if output == '' and process.poll() is not None:
	    break
	if output:
            stdoutdata = stdoutdata + output
	    logging.debug(output.strip())
            """
            if  in output.strip():
                logging.warning("crash detected")
                process.kill()
                break
            """

    stderrdata = process.stderr.read()
    assert(stdoutdata != "")

    return process.returncode, stdoutdata, stderrdata

def process_mutants(name):

    mutations = []
    with open(name, 'rb') as csvfile:
        mutants = csv.reader(csvfile, delimiter=FRAMAC_DELIM, quotechar='|')
        for row in mutants:
            mutated_file = row[0]
            original_file = row[1].split(':')[0]
            line_num = row[1].split(':')[1]
            patch = row[1].split(':')[2]
            mutation = { "orig_name": original_file, "mut_name": mutated_file, "patch": patch, "line_num": line_num }
            mutations.append(mutation)

        return mutations


def filter_mutants(mut_list, orig_name):

    #return list(filter(lambda m: m["orig_name"] != orig_name, mut_list))
    mutants = []
    for m in mut_list:
        if m["orig_name"] != orig_name:
            logging.warning("ignore mutations in a header %s", m["orig_name"])
            continue
        mutants.append(m)

    return mutants


def dump_json_results(struct, name):
    logging.info("dump JSON results to a %s" % name)
    with open(name, 'w') as outfile:
        json.dump(struct, outfile)


def signal_handler(signal, frame):
    sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)


def cleanup_builddir(src_path):

    basename = os.path.basename(src_path)
    name, extension = os.path.splitext(basename)
    shutil.move(FRAMAC_SUMMARY, name + ".csv")
    os.unlink(FRAMAC_SUMMARY)
    os.unlink(basename)
    mask = name + "_*" + extension
    logging.info("remove files with mutations (%s)" % mask)
    map(os.unlink, glob.glob(mask))
    logging.info("restore backup of target source file")
    shutil.copyfile(src_path + "_", src_path)


def html_output(report, name):
    logging.info("dump HTML results to a %s" % name)
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        sys.stderr.write(
                "HTML Output depends on jinja2. `pip install jinja2` first")
        sys.exit(2)

    cwd = ''
    if not os.path.exists(cwd):
        cwd = os.path.dirname(os.path.abspath(__file__))
    env = Environment(loader=FileSystemLoader(cwd),
                      autoescape=select_autoescape(['html']))
    output = env.get_template(TEMPLATE).render(
            title='KOS mutation testing report',
            date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
            report=report)
    with open(name, 'w') as report:
        report.write(output)


def main():

    """
    results = [
                { "name": "", "mutations":
                                [
                                    { "orig_name": "",
                                      "mut_name": "",
                                      "patch": "",
                                      "line_num": 0,
                                      "status": "" }
                                ]
                }
              ]
    """

    target_sources = []
    arg = argparse.ArgumentParser()
    arg.add_argument(
      "--sources",
      nargs="*",
      type=str,
      default=[],
    )

    args = arg.parse_args()
    if len(args.sources) == 0:
        target_sources = [ f for f, reason in SOURCE_FILES.iteritems() if not reason ]
    else:
        target_sources = args.sources

    print "Scheduled source files:", target_sources
    target_src_path = target_sources[0]

    assert(is_tool('frama-c') == True), "frama-c is not found in a system"

    logging.info("cleanup a project (%s)" % CLEANUP_CMD)
    rc, build_log, stderr = execute_command(CLEANUP_CMD)
    if rc != 0:
        logging.warning("cleanup finished with non-zero exit code")
        logging.warning(stderr)
        sys.exit(1)

    # getting build log
    env = os.environ.copy()
    env["CPPCHECK"] = "echo"
    logging.info("building a project (%s)" % TEST_CMD)
    rc, build_log, stderr = execute_command(TEST_CMD, env)
    if rc != 0:
        logging.warning("build finished with non-zero exit code")
        logging.warning(stderr)
        sys.exit(1)

    # TODO: process unit tests results

    target_basename = os.path.basename(target_src_path)
    logging.info("#################################################")
    logging.info("%s" % target_src_path)
    logging.info("#################################################")
    logging.info("create backup of a target source file")
    shutil.copyfile(target_src_path, target_src_path + "_")
    logging.info("copy target source file to a build dir")
    source = os.path.join(os.getcwd(), target_basename)
    shutil.copyfile(target_src_path, source)

    with open(source, 'a') as src:
        src.write(MAIN_FUNC_STUB)

    build_str = ""
    for s in build_log.split('\n'):
        if os.path.abspath(target_src_path) in s.split(' '):
            build_str = s
            logging.info("found build string of %s" % target_src_path)
            break

    logging.debug(build_str)
    assert(build_str != ""), "length of build string is zero"

    cmd = FRAMAC_CMD % (process_build_str(build_str, os.path.abspath(target_src_path)), source)
    logging.info("frama-c command-line %s" % cmd)
    rc = call(cmd, shell=True)
    if rc != 0:
        logging.warning("execution of Frama-C finished with non-zero exit code.")
        logging.warning(stderr)
        # TODO: cleanup and continue
        sys.exit(1)

    assert(os.path.exists(FRAMAC_SUMMARY) == True), "summary.csv is not found"

    # Format: ['sample_1001.c', 'sample.c:2424: `+` --> `*`']
    mutants = process_mutants(FRAMAC_SUMMARY)
    mutants = filter_mutants(mutants, target_basename)

    cnt = 1
    result = { "name": target_src_path, "mutations": [] }
    for m in mutants:
        logging.info("===== [%s/%s] processing %s", str(cnt), str(len(mutants)), os.path.basename(m["mut_name"]))
        logging.info("%s:%s (%s)", m["mut_name"], m["line_num"], m["patch"])
        # TODO: process unit tests results
        logging.info("replace original source file by mutated one")
        shutil.copyfile(m["mut_name"], target_src_path)
        logging.info("building")
        status, stdout, stderr = execute_command(BUILD_CMD)
        logging.info("return code is %s" % str(status))
        if status == 0:
            logging.info("running tests")
            status, stdout, stderr = execute_command(TEST_CMD)
            logging.info("return code is %s" % str(status))
            if status != 0:
                print stderr
        m["status"] = status
        m["stderr"] = stderr.encode('utf-8').strip()
        m["stdout"] = stdout.encode('utf-8').strip()
        result["mutations"].append(m)
        cnt += 1
        dump_json_results(result, target_basename + ".json")
        html_output(result, target_basename + ".html")

    cleanup_builddir(target_src_path)

if __name__ == '__main__':
    sys.exit(main())