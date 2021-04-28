#!/usr/bin/env python3

"""Wrap ldd *nix utility to determine shared libraries required by a program."""

import collections
import copy
import json
import pathlib
import re
import subprocess
from typing import Any, Dict, List, Mapping, Optional, TextIO

DEPENDENCY_ATTRIBUTES = ['soname', 'path', 'found', 'mem_address', 'unused']

class Dependency:
    """
    Represent a shared library required by a program.

    :ivar found: True if ``ldd`` could resolve the library
    :vartype found: bool

    :ivar soname: library name
    :vartype soname: Optional[str]

    :ivar path: path to the library
    :vartype path: Optional[pathlib.Path]

    :ivar mem_address: hex memory location
    :vartype mem_address: Optional[str]

    :ivar unused: library not used
    :vartype unused: Optional[bool]
    """

    def __init__(self,
                 found: bool,
                 soname: Optional[str] = None,
                 path: Optional[pathlib.Path] = None,
                 mem_address: Optional[str] = None,
                 unused: Optional[bool] = None) -> None:
        """Initialize the dependency with the given values."""
        self.soname = soname
        self.path = path
        self.found = found
        self.mem_address = mem_address
        self.unused = unused

    def __str__(self):
        """Transform the dependency to a human-readable format."""
        return "soname: {}, path: {}, found: {}, mem_address: {}, unused: {}" \
               "".format(self.soname, self.path, self.found,
                         self.mem_address, self.unused)

    def as_mapping(self):
        """
        Transform the dependency to a mapping.

        Can be converted to JSON and similar formats.
        """
        return collections.OrderedDict([("soname", self.soname),
                                        ("path", str(self.path)),
                                        ("found", self.found),
                                        ("mem_address", self.mem_address),
                                        ("unused", self.unused)])


_MEM_ADDRESS_RE = re.compile(r'^\s*\(([^)]*)\)\s*$')


def _strip_mem_address(text: str) -> str:
    r"""
    Strip the space and brackets from the mem address in the output.

    :param text: to be stripped
    :return: bare mem address

    >>> _strip_mem_address('(0x00007f9a1a329000)')
    '0x00007f9a1a329000'

    >>> _strip_mem_address(' (0x00007f9a1a329000) ')
    '0x00007f9a1a329000'

    >>> _strip_mem_address('\t(0x00007f9a1a329000)\t')
    '0x00007f9a1a329000'
    """
    mtch = _MEM_ADDRESS_RE.match(text)
    if not mtch:
        raise RuntimeError(("Unexpected mem address. Expected to match {}, "
                            "but got: {!r}").format(_MEM_ADDRESS_RE.pattern,
                                                    text))

    return mtch.group(1)


def _parse_line(line: str) -> Optional[Dependency]:
    """
    Parse single line of ldd output.

    :param line: to parse
    :return: dependency or None if line was empty

    """
    found = not 'not found' in line
    parts = [part.strip() for part in line.split(' ')]
    # There are two types of outputs for a dependency, with or without soname.
    # The VDSO is a special case (see https://man7.org/linux/man-pages/man7/vdso.7.html)
    #
    # For example:
    # VDSO (Ubuntu 16.04): linux-vdso.so.1 =>  (0x00007ffd7c7fd000)
    # VDSO (Ubuntu 18.04): linux-vdso.so.1 (0x00007ffe2f993000)
    # with soname: 'libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f9a19d8a000)'
    # without soname: '/lib64/ld-linux-x86-64.so.2 (0x00007f9a1a329000)'
    # with soname but not found: 'libboost_program_options.so.1.62.0 => not found'
    # with soname but without rpath: 'linux-vdso.so.1 =>  (0x00007ffd7c7fd000)'
    # pylint: enable=line-too-long
    if '=>' in line:
        if len(parts) != 4:
            raise RuntimeError(
                "Expected 4 parts in the line but found {}: {}".format(
                    len(parts), line))

        soname = None
        dep_path = None
        mem_address = None
        if found:
            soname = parts[0]
            if parts[2] != '':
                dep_path = pathlib.Path(parts[2])

            mem_address = _strip_mem_address(text=parts[3])
        else:
            if "/" in parts[0]:
                dep_path = pathlib.Path(parts[0])
            else:
                soname = parts[0]

        return Dependency(
            soname=soname, path=dep_path, found=found, mem_address=mem_address)
    else:
        if len(parts) != 2:
            raise RuntimeError(
                "Expected 2 parts in the line but found {}: {}".format(
                    len(parts), line))

        if parts[0].startswith('linux-vdso'):
            soname = parts[0]
            path = None
        else:
            soname = None
            path = pathlib.Path(parts[0])

        return Dependency(
            soname=soname,
            path=path,
            found=True,
            mem_address=_strip_mem_address(text=parts[1]))


def list_dependencies(path: pathlib.Path,
                      unused: bool = False,
                      env: Optional[Dict[str, str]] = None) -> List[Dependency]:
    """
    Retrieve a list of dependencies of the given binary.

    >>> path = pathlib.Path("/bin/ls")
    >>> deps = list_dependencies(path=path)
    >>> deps[0].soname
    'linux-vdso.so.1'

    :param path: path to a file
    :param unused:
        if set, check if dependencies are actually used by the program
    :param env:
        the environment to use.

        If ``env`` is None, currently active env will be used.
        Otherwise specified env is used.
    :return: list of dependencies
    """
    # We need to use /usr/bin/env since Popen ignores the PATH,
    # see https://stackoverflow.com/questions/5658622
    proc = subprocess.Popen(
        ["/usr/bin/env", "ldd", path.as_posix()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=env)

    out, err = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(
            "Failed to ldd external libraries of {} with code {}:\nout:\n{}\n\n"
            "err:\n{}".format(path, proc.returncode, out, err))

    dependencies = _cmd_output_parser(cmd_out=out)

    if unused:
        proc_unused = subprocess.Popen(
            ["/usr/bin/env", "ldd", "--unused",
             path.as_posix()],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=env)

        out_unused, err_unused = proc_unused.communicate()
        # return code = 0 -> no unused dependencies,
        # return code = 1 -> some unused dependencies
        if proc_unused.returncode not in [0, 1]:
            raise RuntimeError(
                "Failed to ldd external libraries of {} with code {}:\nout:\n"
                "{}\n\nerr:\n{}".format(path, proc.returncode, out_unused,
                                        err_unused))

        dependencies = _update_unused(
            dependencies=dependencies, out_unused=out_unused)

    return dependencies


def _cmd_output_parser(cmd_out):
    """
    Parse the command line output.

    :param cmd_out: command line output
    :return: List of dependencies
    """
    dependencies = []

    lines = [line.strip() for line in cmd_out.split('\n') if line.strip() != '']

    if len(lines) == 0:
        return []

    # This is a special case of a static library. The first line refers
    # to the library and the second line indicates that the library
    # was statically linked.
    if len(lines) == 2 and lines[1] == 'statically linked':
        return []

    for line in lines:
        dep = _parse_line(line=line)
        if dep is not None:
            dependencies.append(dep)

    return dependencies


def _update_unused(dependencies, out_unused):
    """
    Set "unused" property of the dependencies.

    Updates the "unused" property of the dependencies using the output string
    from ldd command.

    :param dependencies: List of dependencies
    :param out_unused: output from command ldd --unused
    :return: updated list of dependencies
    """
    unused_dependencies = []

    for line in [
            line.strip() for line in out_unused.split('\n')
            if line.strip() != ''
    ]:
        # skip first line because it's no dependency
        if line != "Unused direct dependencies:":
            unused_dependencies.append(pathlib.Path(line.strip()))

    for dep in dependencies:
        dep.unused = dep.path in unused_dependencies

    return dependencies


def _output_json(deps, stream):
    """
    Output dependencies in a JSON format to the ``stream``.

    :param deps: list of dependencies
    :param stream: output stream
    :return:
    """
    json.dump(obj=[dep.as_mapping() for dep in deps], fp=stream, indent=2)


def shlib2package(path):
    proc = subprocess.Popen(
        ["/usr/bin/dpkg", "-S", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True)
    out, err = proc.communicate()
    """
    if proc.returncode != 0:
        raise RuntimeError(
            "Failed to resolve package name for file {} with code {}:\nout:\n{}\n\n"
            "err:\n{}".format(path, proc.returncode, out, err))
    """
    package_name = out

    return package_name

"""
deb-based: dpkg -S /bin/ls
rpm-based: rpm -q --whatprovides
openbsd: rpm -q --whatprovides
freebsd: pkg_info -W /usr/local/bin/sudo
"""
def _find_packages(deps, stream):
    for dep in deps:
        # print(str(dep.path), str(dep.unused))
        so_path = str(dep.path)
        print(shlib2package(so_path))

    # stream.write(_format_table(table))

import pathlib
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-f",
        "--format",
        help="Output format",
        default='verbose',
        choices=['verbose', 'json'])
    parser.add_argument("path", help="Specify path to the binary")
    args = parser.parse_args(sys.argv[1:])
    if pathlib.Path(args.path).is_dir():
        parser.error("Path '{}' is a dir. Path to file required. Check out "
                     "--help for more information.".format(args.path))

    if not pathlib.Path(args.path).is_file():
        parser.error(
            "Path '{}' is not a file. Path to file required. Check out "
            "--help for more information.".format(args.path))
    path = pathlib.Path(args.path)
    deps = list_dependencies(path=path, unused=True)
    _output_json(deps=deps, stream=sys.stdout)
    _find_packages(deps=deps, stream=sys.stdout)


if __name__ == "__main__":
    main()
