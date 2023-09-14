Примеры:

- https://github.com/Zac-HD/hypothesis-jsonschema/blob/master/src/hypothesis_jsonschema/_impl.py
- https://github.com/HypothesisWorks/hypothesis/blob/master/hypothesis-python/src/hypothesis/extra/pytz.py
- https://docs.python.org/2/library/stat.html <--- флаги

## hypothesis-fsobj

[Hypothesis](https://hypothesis.readthedocs.io/en/latest/) extension for
generating filesystem objects.

There are many edge cases with testing applications working with filesystems
(backup, synchronization etc).  This testsuite contains testcases created such
edge cases and evaluated behavior of application.  Testsuite helps to compare
[backup applications](https://github.com/restic/others) one by one and choose a
best one.

### Example

```python

    from hypothesis import given
    from hypothesis_fspaths import fspaths

    @given(fspaths())
    def test_open_file(path):
        try:
            open(path).close()
        except IOError:
            pass
```

### Papers

- https://danluu.com/filesystem-errors/
- https://danluu.com/deconstruct-files/
- [CRIU: Filesystems pecularities](https://criu.org/Filesystems_pecularities)
- [Further Torture: More Testing of Backup and Archive Programs](https://www.usenix.org/legacy/events/lisa03/tech/full_papers/zwicky/zwicky_html/index.html)
- [Further Torture: More Testing of Backup and Archive Programs](https://www.usenix.org/legacy/events/lisa2003/tech/full_papers/zwicky/zwicky.pdf)
- [Torture-testing Backup and Archive Programs: Things You Ought to Know But Probably Would Rather Not](http://www.coredumps.de/doc/dump/zwicky/testdump.doc.html)
- [Myths programmers believe about file paths](https://yakking.branchable.com/posts/falsehoods-programmers-believe-about-file-paths/)

### Похожие программы:

- [winfsp tests](https://github.com/billziss-gh/winfsp/blob/master/tst/winfsp-tests/)
- [xfstests-bld](https://github.com/tytso/xfstests-bld)
- [xfstests](https://github.com/kdave/xfstests/tree/master/src)
- [borg testsuite](https://github.com/borgbackup/borg/tree/master/src/borg/testsuite)
- [rsync testsuite](https://github.com/freenas/rsync/tree/master/testsuite)
- [charybdefs](https://github.com/scylladb/charybdefs)
- [fakedatafs](https://github.com/restic/fakedatafs)
- [fakefs](https://github.com/fakefs/fakefs)

## Эвристики:

- `common`: no changes in content (calculate crypto hash)
- `size`: empty file
- `size`: empty directory
- `type`: character device file.
- `type`: block device file
- `type`: regular file
- `type`: directory with files
- `type`: local socket file
- `type`: named pipe
- `type`: symbolic link
- `type`: hard link
- `name`: ascii
- `name`: utf-8
- `name`: unprintable symbols (escape and bell)
- `name`: whitespace
- `name`: contain * or ? characters (if you use of shell's globbing feature, you need to escape or quote glob characters)
- `name`: contain "\n"
- `name`: contain "." or ".."
- `name`: illegal filenames ("/" on Unix, ":" on Windows)
- `name`: illegal filenames (Windows: CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, and LPT9)
- `name`: name.extension
- `name`: name..extension
- `name`: name.extension where extension has more than three symbols
- `name`: path components are separated with /
- `name`: uppercase symbols
- `name`: lowercase symbols
- `name`: max length
- `name`: files have visibly distinct file names/paths ("control" and "сontrol")
- `path`: MAXPATHLEN and MAXCOMPLEN ([pathconf(3)](http://man7.org/linux/man-pages/man3/pathconf.3.html))
- `path`: longer than PATH_MAX
- `path`: https://eklitzke.org/path-max-is-tricky
- `path`: path components longer than PATH_MAX
- `path`: foo and foo/../foo always point to the same directory
- `path`: [patterns](https://github.com/borgbackup/borg/blob/master/src/borg/testsuite/shellpattern.py), [patterns](https://github.com/borgbackup/borg/blob/master/src/borg/testsuite/patterns.py)
- `access`: -wx (run with root permissions)
- `access`: same file permissions before backup and after restore
- `content`: sparse file
- `content`: file with nulls
- `content`: unwritten sync
- `metadata`: xattr
- `metadata`: atime
- `metadata`: mtime
- `metadata`: ctime
- https://eklitzke.org/path-max-is-tricky

### TODO

- https://github.com/jmcgeheeiv/pyfakefs/
- https://docs.pyfilesystem.org/en/latest/
- https://github.com/kdave/xfstests/blob/master/src/af_unix.c
- https://github.com/kdave/xfstests/blob/master/src/fs_perms.c
- https://github.com/kdave/xfstests/blob/master/src/fsync-tester.c
- https://github.com/kdave/xfstests/blob/master/src/genhashnames.c
- https://github.com/kdave/xfstests/blob/master/src/holes.c
- https://github.com/kdave/xfstests/blob/master/src/listxattr.c
- https://github.com/kdave/xfstests/blob/master/src/nametest.c
- https://github.com/kdave/xfstests/blob/master/src/t_holes.c
- https://github.com/kdave/xfstests/blob/master/src/test-nextquota.c
- https://github.com/kdave/xfstests/blob/master/src/truncfile.c
- https://github.com/kdave/xfstests/blob/master/src/unwritten_sync.c
