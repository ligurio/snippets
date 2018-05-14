## Model-checking

### SPIN case studies:

- [PostgreSQL pgpool](http://d.hatena.ne.jp/interdb/touch/20100815/1281809853)
- [Linux kernel RCU](https://lwn.net/Articles/279077/)
- Formal analysis of a space-craft controller using SPIN
- [Network protocol for real-time sharing between graphical applications](https://github.com/verse/verse/tree/master/misc/promela)
- "Formal verification of requirements using SPIN: a case study on Web services"
- "Model checking embedded systems with PROMELA"
- "Using SPIN to model cryptographic protocols"
- "Using SPIN model checking for flight software verification"
- "Analysis and Verification of Two-Phase Commit & Three-Phase Commit Protocols"
- "A Formal Model of Crash Recovery in a Distributed System"
- http://spinroot.com/spin/success.html
- http://www.imm.dtu.dk/~albl/promela.html
- [Modeling and Formal Verification of DHCP Using SPIN](https://pdfs.semanticscholar.org/6ddd/d0951f9596526f138faa68304485a6a052e2.pdf)

- [Applications for the Checker – A Survey(]www.tucs.fi/publications/attachment.php?fname=TR782.pdf) - Ville R. Koskinen | Juha Plosila
- [Comparisons of Alloy and Spin](http://www.pamelazave.com/compare.html)
- [Specifying and Verifying Concurrent C Programs with TLA+](https://cedric.cnam.fr/fichiers/art_3439.pdf)


### TLA+ case studies:

- [Elasticsearch](https://github.com/elastic/elasticsearch-formal-models)
- [MongoDB](https://github.com/visualzhou/mongo-repl-tla)
- https://github.com/tlaplus/Examples
- [Debugging Designs](http://www.hpts.ws/papers/2011/sessions_2011/Debugging.pdf)
- https://www.hillelwayne.com/post/list-of-tla-examples/

### BLAST case studies

- [The Software Model Checker BLAST: Applications to Software Engineering](http://pub.ist.ac.at/~tah/Publications/the_software_model_checker_blast.pdf)
- "Applicability of the BLAST Model Checker: An Industrial Case Study"

### Learning exercises:

- Model a lift controller: the lift has n doors, and you will have to model
both the behavior and safety conditions, for example that once at the top, the
lift will no more move up, or that we should not have two doors opened at the
same time, and no door opened when the cabin is not in front of it, and many
more.

- Model traffic light controller: for the easy example, a simple crossing, with
many constraints, such as facing lights are synchronized, and if one axis has
green, tho other has red. You can refine the thing adding detection of traffic
condition, and timing.

- Model a Washing machine: especially the door locker, and simple programs.
Prove that there is no way to lock the door, that is there is always a solution
to get your clothes free (even if wet) in a limited time (you will have to
consider a water elimination step), without getting too much water on your
floor.
