## Model-checking

### Spin case studies:

- [PostgreSQL pgpool](http://d.hatena.ne.jp/interdb/touch/20100815/1281809853)
- [Linux kernel RCU](https://lwn.net/Articles/279077/)
- Formal analysis of a space-craft controller using SPIN
- [Network protocol for real-time sharing between graphical applications](https://github.com/verse/verse/tree/master/misc/promela)

### TLA+ case studies

- [Elasticsearch](https://github.com/elastic/elasticsearch-formal-models)
- [MongoDB](https://github.com/visualzhou/mongo-repl-tla)
- https://github.com/tlaplus/Examples
- [Debugging Designs](http://www.hpts.ws/papers/2011/sessions_2011/Debugging.pdf)

### Learning exercises

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
