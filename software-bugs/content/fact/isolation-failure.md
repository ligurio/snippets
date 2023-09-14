---
title: "Isolation Failure"
---

Isolation Failure is any failure event during which two concurrently executing
components unexpectedly access a shared resource simultaneously via an
interference path, thereby violating the components' spatial or temporal
isolation. These shared resources can be *processor-internal* (e.g., L3 cache,
system bus, memory controller, I/O controllers, and interconnects) or
*processor-external* (e.g., main memory, I/O devices, networks, and subsystems).
Note that a temporal isolation failure can lead to the failure of
hard-real-time requirements (e.g., unacceptable response time and unacceptable
jitter).

Category: Concurrency
