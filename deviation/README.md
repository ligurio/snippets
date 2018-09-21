## deviation

is a tool to detect anomalies which is robust, from a statistical standpoint,
in the presence of seasonality and an underlying trend. The deviation tool can
be used in wide variety of contexts. For example, detecting anomalies in system
metrics after a new software release, user engagement post an A/B test, or for
problems in software testing.

### Examples

 $ DATA="http://www-personal.umich.edu/~mejn/cp/data/sunspots.txt"
 $ curl -s $DATA | awk '{ print $2 }' | deviation

### Benchmarks

- http://www.dbs.ifi.lmu.de/research/outlier-evaluation/
- http://odds.cs.stonybrook.edu/

### 

- https://github.com/yzhao062/Pyod
- https://github.com/lytics/anomalyzer
- https://github.com/yzhao062/anomaly-detection-resources
