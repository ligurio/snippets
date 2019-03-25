
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

- [Hippie problem](https://spcl.inf.ethz.ch/Teaching/2016-dphpc/recitation/spin_tutorial.pdf):
4 Hippies want to cross a bridge. The bridge is fragile, it can only crossed by
<= 2 people at a time with a torchlight. The hippies have one torchlight and
want to reach the other side within one hour. Due to different degrees of
intoxication they require different amounts of time to cross the bridge: 5, 10,
20 and 25 minutes.  If a pair crosses the bridge, they can only move // at the
speed of the slower partner.
