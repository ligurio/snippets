---
title: "ABA"
---

The ABA problem occurs during synchronization, when a location is read twice,
has the same value for both reads, and "value is the same" is used to indicate
"nothing has changed". However, another thread can execute between the two
reads and change the value, do other work, then change the value back, thus
fooling the first thread into thinking "nothing has changed" even though the
second thread did work that violates that assumption.

Category: Concurrency

Details: 

* [Wikipedia: ABA](https://en.m.wikipedia.org/wiki/ABA_problem)
