# perfmon-agent-c

is a server metrics fetching agent, based on [SIGAR](https://github.com/hyperic/sigar) open source library and written on C. [Apache JMeter](https://jmeter.apache.org/) can retrieve server metrics with [PerfMon](http://jmeterplugins.com/wiki/PerfMon/index.html) plugin and this agent.

- Пример: https://github.com/couchbase/sigar/blob/master/src/sigar.c
- https://libstatgrab.org/


### How-To Setup:

- https://www.testautomationguru.com/jmeter-server-performance-metrics-collector/
- https://www.blazemeter.com/blog/how-monitor-your-server-health-performance-during-jmeter-load-test/

### Supported commands:

List of metrics was created using [PerfMonMetrics](http://jmeterplugins.com/wiki/PerfMonMetrics/index.html) and source code of [perfmon-agent](https://github.com/undera/perfmon-agent) written on Java.


- `exit` - terminates current client session and closes connection to agent, no parameters
- `test` - test if server is alive, no parameters
- `shutdown` - terminate all client connections and shutdown agent process, no parameters
- `interval` - change metrics reporting interval used in 'metrics' command, single parameter is integer value in seconds. Interval can be changed in the middle of metrics reporting. Example: `interval:5`

Most of the metrics accepts single parameter called 'type'. This parameter specifies which particular number you want to collect. There is default metric type for each metric category that will be collected if no 'type' parameter specified (see lists below, bold first item in each category).

Some metric types are commonly used and considered primary, leaving some rarely used types as additional. Make note that not all metrics available on all platforms, we depend on SIGAR API capabilities here.

Some metrics allow specifying particular object to monitor, you may specify selector parameter to monitor values only for this object:

- `name`, `pid` and `ptql` - processes
- `core` - number of CPU on a multicore systems
- `fs` - mount point of filesystem
- `iface` - name of a network interface

Make note that metric types are different for per-process and total metrics for CPU and Memory.

Some example metric parameter strings:

- `metrics` - starts automatic metrics collection, parameters are metrics list to collect, described below. Example: `metrics:cpu`
- `metrics-single` - calls single metric collection iteration.

Fields number is metric-type specific. Possible metric types are:

- Total: `cpu:[combined,idle,irq,nice,softirq,stolen,system,user,iowait]`
- Per process: `cpu:[percent,total,system,user]`
- Total memory: `memory:[virtual,shared,pagefaults,majorfaults,minorfaults,resident]`
- Per process: `memory:[actualfree,actualused,free,freeperc,ram,total,used,usedperc]`
- Swap: `swap:[pagein,pageout,free,total,used]`
- Disk IO: `disks:[available,queue,readbytes,reads,service,writebytes,writes,files,free,freefiles,total,useperc,used]`
- Network IO: `network:[bytesrecv,rxdrops,rxerr,rxframe,rxoverruns,rx,bytessent,txcarrier,txcollisions,txdrops,txerr,txoverruns,used,speed,tx]`
- TCP: `tcp:[bound,close,close_wait,closing,estab,fin_wait1,fin_wait2,idle,inbound,last_ack,listen,outbound,syn_recv,time_wait]`
- Tail: `tail:<filename>`
- Process execution: `exec:<command>:<param>:<param>`

Examples:

- `combined` - measure total CPU usage, equals to 100-idle value
- `core=2:user` - measure user process CPU usage for third core in system (core numbering starts at 0)
- `name=java#2:user` - will monitor second java process instance for user time spent
- `pid=14523:percent` - will monitor process with PID 14523 for total CPU usage percentage 
- `name=httpd` - omitting metric type will use default 'percent'
- `fs=/home:writes` - will monitor /home filesystem for number of write operations
- `iface=eth0:tx` - will monitor interface eth0 for transmitted packet rate

```
metrics-single:memory
82.40174605900177

metrics-single:cpu      memory
1.743090990034588       82.40096038578609

metrics-single:exec:/bin/sh:-c:free | grep Mem | awk '{print $7}'
1152488
```
