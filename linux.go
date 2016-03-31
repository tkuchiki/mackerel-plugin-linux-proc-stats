package main

import (
	"bufio"
	"flag"
	"fmt"
	mp "github.com/mackerelio/go-mackerel-plugin-helper"
	"github.com/mackerelio/mackerel-agent/logging"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

var logger = logging.GetLogger("metrics.plugin.linux-proc-stats")

// /proc/PID/stat fileds
const (
	Comm       = 1
	State      = 2
	UTime      = 13
	STime      = 14
	CUTime     = 15
	CSTime     = 16
	NumThreads = 19
	StartTime  = 21
	VSize      = 22
	Rss        = 23
)

// Process Status
type Process struct {
	State      string
	UTime      float64
	STime      float64
	CUTime     float64
	CSTime     float64
	StartTime  float64
	NumThreads float64
	VSize      float64
	RSS        float64
}

// Processes slice of Process
type Processes []Process

var uptime float64
var cpuTick float64
var metricKey string

// CPUUsage retrieve cpu usage
func (p *Process) CPUUsage() float64 {
	total := p.UTime + p.STime + p.CUTime + p.CSTime
	sec := uptime - (p.StartTime / cpuTick)
	return 100 * ((total / cpuTick) / sec)
}

// LinuxProcStatsPlugin mackerel plugin for Linux processes
type LinuxProcStatsPlugin struct {
	Tempfile             string
	Pid                  string
	FollowChildProcesses bool
}

// FetchMetrics interface for mackerelplugin
func (lp LinuxProcStatsPlugin) FetchMetrics() (stats map[string]interface{}, err error) {
	var ps Processes
	p, err := readProcPIDStat(statFile(lp.Pid))
	if err != nil {
		return stats, err
	}

	ps = append(ps, p)

	if lp.FollowChildProcesses {
		options := []string{"--ppid", lp.Pid, "-o", "pid", "--no-headers"}
		ps, err = childStats(ps, options)
		if err != nil {
			return stats, err
		}
	}
	running, numThreads, vSize, rss, cpuUsage := sumStats(ps)
	stats = make(map[string]interface{})
	stats["running"] = running
	stats["processes"] = float64(len(ps))
	stats["threads"] = numThreads
	stats["vsize"] = vSize
	stats["rss"] = rss
	stats["usage"] = cpuUsage

	return stats, err
}

// GraphDefinition interface for mackerelplugin
func (lp LinuxProcStatsPlugin) GraphDefinition() map[string](mp.Graphs) {
	comm, err := readProcPIDComm(lp.Pid)
	if err != nil {
		logger.Errorf("Failed to read /proc/PID/stat comm. %s", err)
		return map[string](mp.Graphs){}
	}

	return map[string](mp.Graphs){
		fmt.Sprintf("%s_process.num", comm): mp.Graphs{
			Label: fmt.Sprintf("%v Running", comm),
			Unit:  "integer",
			Metrics: [](mp.Metrics){
				mp.Metrics{Name: "running", Label: "Current Running Processes", Diff: false},
				mp.Metrics{Name: "processes", Label: "All Processes", Diff: false},
				mp.Metrics{Name: "threads", Label: "Num Threads", Diff: false},
			},
		},
		fmt.Sprintf("%s_process.cpu", comm): mp.Graphs{
			Label: fmt.Sprintf("%v CPU", comm),
			Unit:  "float",
			Metrics: [](mp.Metrics){
				mp.Metrics{Name: "usage", Label: "CPU Usage", Stacked: true, Diff: false},
			},
		},
		fmt.Sprintf("%s_process.memory", comm): mp.Graphs{
			Label: fmt.Sprintf("%v Memory", comm),
			Unit:  "bytes",
			Metrics: [](mp.Metrics){
				mp.Metrics{Name: "vsize", Label: "Vsize", Stacked: false, Diff: false},
				mp.Metrics{Name: "rss", Label: "RSS", Stacked: false, Diff: false},
			},
		},
	}
}

func readPIDFile(f string) (pid string, err error) {
	fp, err := os.Open(f)
	if err != nil {
		return pid, err
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	scanner.Scan()
	pid = scanner.Text()

	return pid, err
}

func readStatFile(f string) ([]string, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return []string{""}, err
	}

	s := strings.Split(string(b), " ")
	return s, err
}

func readProcPIDComm(pid string) (comm string, err error) {
	if metricKey == "" {
		s, err := readStatFile(statFile(pid))
		if err != nil {
			return comm, err
		}
		comm = strings.Trim(s[Comm], "()")
	} else {
		comm = metricKey
	}

	return comm, err
}

func readProcPIDStat(f string) (p Process, err error) {
	s, err := readStatFile(f)
	if err != nil {
		return p, err
	}

	numThreads, err := strconv.ParseFloat(s[NumThreads], 64)
	if err != nil {
		return p, err
	}

	vSize, err := strconv.ParseFloat(s[VSize], 64)
	if err != nil {
		return p, err
	}

	rss, err := strconv.ParseFloat(s[Rss], 64)
	if err != nil {
		return p, err
	}

	utime, err := strconv.ParseFloat(s[UTime], 64)
	if err != nil {
		return p, err
	}

	stime, err := strconv.ParseFloat(s[STime], 64)
	if err != nil {
		return p, err
	}

	cutime, err := strconv.ParseFloat(s[CUTime], 64)
	if err != nil {
		return p, err
	}

	cstime, err := strconv.ParseFloat(s[CSTime], 64)
	if err != nil {
		return p, err
	}

	startTime, err := strconv.ParseFloat(s[StartTime], 64)
	if err != nil {
		return p, err
	}

	p = Process{
		State:      s[State],
		NumThreads: numThreads,
		VSize:      vSize,
		RSS:        rss * float64(os.Getpagesize()),
		UTime:      utime,
		STime:      stime,
		CUTime:     cutime,
		CSTime:     cstime,
		StartTime:  startTime,
	}

	return p, err
}

func statFile(pid string) string {
	return fmt.Sprintf("/proc/%v/stat", strings.TrimSpace(pid))
}

func childStats(ps Processes, options []string) (Processes, error) {
	cmd := exec.Command("ps", options...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ps, err
	}

	cmd.Start()
	scanner := bufio.NewScanner(stdout)

	var p Process
	for scanner.Scan() {
		childPid := scanner.Text()
		p, err = readProcPIDStat(statFile(childPid))
		if err == nil {
			ps = append(ps, p)
		}
	}

	cmd.Wait()

	return ps, err
}

func sumStats(ps Processes) (running, numThreads, vSize, rss, cpuUsage float64) {
	for _, p := range ps {
		if p.State == `R` {
			running++
		}
		numThreads += p.NumThreads
		vSize += p.VSize
		rss += p.RSS
		cpuUsage += p.CPUUsage()
	}

	return running, numThreads, vSize, rss, cpuUsage
}

func getCPUTick() (tick float64, err error) {
	var out []byte
	out, err = exec.Command("/usr/bin/getconf", "CLK_TCK").Output()

	if err != nil {
		return tick, err
	}

	tick, err = strconv.ParseFloat(strings.TrimSpace(string(out)), 64)

	return tick, err
}

func getUptime() (float64, error) {
	sysinfo := syscall.Sysinfo_t{}
	err := syscall.Sysinfo(&sysinfo)

	return float64(sysinfo.Uptime), err
}

func main() {
	optPID := flag.String("pid", "", "PID")
	optPIDFile := flag.String("pidfile", "", "PID file")
	optTempfile := flag.String("tempfile", "", "Temp file name")
	optFollowChildProcesses := flag.Bool("follow-child-processes", false, "Follow child processes")
	optMetricKey := flag.String("metric-key-prefix", "", "Metric key prefix")
	optVersion := flag.Bool("version", false, "Version")
	flag.Parse()

	if *optVersion {
		fmt.Println("0.1")
		os.Exit(0)
	}

	var pid string
	var err error

	if *optPID != "" {
		pid = *optPID
	} else {
		pid, err = readPIDFile(*optPIDFile)
		if err != nil {
			logger.Errorf("Failed to read /proc/%s/stat. %s", pid, err)
		}
	}
	if pid == "" {
		logger.Errorf("Not found pid")
		os.Exit(1)
	}

	metricKey = *optMetricKey

	var procStats LinuxProcStatsPlugin
	procStats.Pid = pid
	procStats.FollowChildProcesses = *optFollowChildProcesses

	uptime, err = getUptime()
	if err != nil {
		logger.Errorf("Failed to fetch uptime. %s", err)
	}

	cpuTick, err = getCPUTick()
	if err != nil {
		logger.Errorf("Failed to fetch cputick. %s", err)
	}

	helper := mp.NewMackerelPlugin(procStats)
	if *optTempfile != "" {
		helper.Tempfile = *optTempfile
	} else {
		helper.Tempfile = "/tmp/mackerel-plugin-linux-proc-stats"
	}

	helper.Run()
}
