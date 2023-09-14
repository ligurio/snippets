---
title: "Race Condition"
---

Race Condition (a.k.a., data race) is the failure condition that exists when
the nondeterministic ordering of multiple operations can result in different,
unexpected and potentially incorrect behaviors. A race condition can occur if
the correct ordering of the operations is not enforced or if shared resources
are not protected from simultaneous access. For example, one thread or process
writes to an unprotected memory location, while another simultaneously accesses
it, thereby corrupting the stored data.

Category: Concurrency

Details: 

* [Wikipedia: Race Condition](https://en.wikipedia.org/wiki/Race_condition)
* [Wikipedia: Time-of-check to time-of-use](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)
