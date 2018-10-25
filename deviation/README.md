## deviation

is a tool to detect anomalies which is robust, from a statistical standpoint,
in the presence of seasonality and an underlying trend. The deviation tool can
be used in wide variety of contexts. For example, detecting anomalies in system
metrics after a new software release, user engagement post an A/B test, or for
problems in software testing.

Outlier detection has been used for centuries to detect and, where appro-
priate, remove anomalous observations from data. Outliers arise due to
mechanical faults, changes in system behaviour, fraudulent behaviour, human
error, instrument error or simply through  natural  deviations  in
populations. Their detection can identify system faults and fraud before
they escalate with potentially catastrophic consequences. It can identify
errors and remove their contaminating effect on the data set and as such to
purify the data for processing. The original outlier detection methods were
arbitrary but now, principled and systematic techniques are used, drawn from
the full gamut of Computer Science and Statistics.

### Examples
```
 $ DATA="http://www-personal.umich.edu/~mejn/cp/data/sunspots.txt"
 $ curl -s $DATA | cut -f2 -d' ' | deviation
 $ curl -s $DATA | cut -f2 -d' ' | gnuplot -p -e "plot '<cat'"
 $ curl -s $DATA | cut -f2 -d' ' | gnuplot -p -e "set terminal dumb; plot '<cat'
```

TODO: identificate deviations in logs and similar logs

### Benchmarks

- http://www.dbs.ifi.lmu.de/research/outlier-evaluation/
- http://odds.cs.stonybrook.edu/
- https://github.com/numenta/NAB
- https://github.com/yui0/catseye/
- https://github.com/attractivechaos/kann
- https://github.com/attractivechaos/sann

### References

- [Automatic Detection of Performance Deviations in the Load Testing of Large Scale Systems] -- Haroon Malik, Hadi Hemmati, Ahmed E. Hassan
- https://github.com/yzhao062/Pyod
- https://github.com/lytics/anomalyzer
- https://github.com/blue-yonder/tsfresh
- https://github.com/yzhao062/anomaly-detection-resources
