## deviation

is a tool to detect anomalies which is robust, from a statistical standpoint,
in the presence of seasonality and an underlying trend. The deviation tool can
be used in wide variety of contexts. For example, detecting anomalies in system
metrics after a new software release, user engagement post an A/B test, or for
problems in software testing.

### Examples

 $ DATA="http://www-personal.umich.edu/~mejn/cp/data/sunspots.txt"
 $ curl -s $DATA | cut -f2 -d' ' | deviation
 $ curl -s $DATA | cut -f2 -d' ' | gnuplot -p -e "plot '<cat'"
 $ echo "1\n2\n4\n8\n16" | gnuplot -e "plot '-' u 0:1 w linespoints" -persist

### Benchmarks

- http://www.dbs.ifi.lmu.de/research/outlier-evaluation/
- http://odds.cs.stonybrook.edu/

### References

- https://github.com/yzhao062/Pyod
- https://github.com/lytics/anomalyzer
- https://github.com/blue-yonder/tsfresh
- https://github.com/yzhao062/anomaly-detection-resources

### TODO

- GSL https://www.gnu.org/software/gsl/
