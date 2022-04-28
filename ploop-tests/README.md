# ploop tests

[Ploop](https://openvz.org/Ploop) is a disk loopback block device, not unlike
loop but with many features like dynamic resize, snapshots, backups etc. The
main idea is to put container filesystem in a file.

## How to run

- setup environment with latest version of [vzkernel](https://openvz.org/Download/kernel) and [ploop](https://openvz.org/Download/ploop) utility
- checkout the latest version of these tests
- ``autoreconf -vi && ./configure``
- run tests with ``make check``
