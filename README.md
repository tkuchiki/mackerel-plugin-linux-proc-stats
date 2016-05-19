# mackerel-plugin-linux-proc-stats
Linux processes metrics plugin for mackerel.io agent.

## Synopsis

```shell
mackerel-plugin-linux-proc-stats -pid=<pid>|-pidfile=<pidfile>|-process-pattern=<process pattern> [-metric-key-prefix=<metric-key-prefix>] [-tempfile=<tempfile>] [-follow-child-processes]
```

```shell
$ ./mackerel-plugin-linux-proc-stats --help
Usage of ./mackerel-plugin-linux-proc-stats:
  -follow-child-processes
        Follow child processes
  -metric-key-prefix string
        Metric key prefix
  -pid string
        PID
  -pidfile string
        PID file
  -process-pattern string
        Match a command against this pattern
  -tempfile string
        Temp file name
  -version
        Version
```

## Requirements

- [getconf](http://linux.die.net/man/1/getconf)

## Example of mackerel-agent.conf

```
[plugin.metrics.linux_proc_stats]
command = "/path/to/mackerel-plugin-linux-proc-stats -pidfile /var/run/nginx.pid -follow-child-processes"
```

```
[plugin.metrics.linux_proc_stats]
command = "/path/to/mackerel-plugin-linux-proc-stats -pidfile /var/run/mackerel-agent.pid"
```

```
[plugin.metrics.linux_proc_stats]
command = "/path/to/mackerel-plugin-linux-proc-stats -process-pattern 'nginx: master process'"
```

## Example

Running threads.

```shell
$ ./mackerel-plugin-linux-proc-stats -pidfile /var/run/mackerel-agent.pid
mackerel-agent_process.memory.vsize     812974080.000000        1458808344
mackerel-agent_process.memory.rss       10448896.000000 1458808344
mackerel-agent_process.num.running      0.000000        1458808344
mackerel-agent_process.num.processes    1.000000        1458808344
mackerel-agent_process.num.threads      26.000000       1458808344
mackerel-agent_process.cpu.usage        0.083986        1458808344
```

Only master process.

```shell
$ ./mackerel-plugin-linux-proc-stats -pidfile /var/run/nginx.pid
nginx_process.cpu.usage 0.000000        1458808477
nginx_process.memory.vsize      107450368.000000        1458808477
nginx_process.memory.rss        3399680.000000  1458808477
nginx_process.num.running       0.000000        1458808477
nginx_process.num.processes     1.000000        1458808477
nginx_process.num.threads       1.000000        1458808477
```

Master process and worker processes.

```shell
$ ./mackerel-plugin-linux-proc-stats -pidfile /var/run/nginx.pid -follow-child-processes
nginx_process.num.running       0.000000        1458808496
nginx_process.num.processes     2.000000        1458808496
nginx_process.num.threads       2.000000        1458808496
nginx_process.cpu.usage 0.000095        1458808496
nginx_process.memory.vsize      215269376.000000        1458808496
nginx_process.memory.rss        7966720.000000  1458808496
```
