// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !noprocesses
// +build !noprocesses

package collector

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

type processCollector struct {
	fs           procfs.FS
	threadAlloc  *prometheus.Desc
	threadLimit  *prometheus.Desc
	threadsState *prometheus.Desc
	procsState   *prometheus.Desc
	pidUsed      *prometheus.Desc
	pidMax       *prometheus.Desc
	logger       log.Logger
}

func init() {
	registerCollector("processes", defaultEnabled, NewProcessStatCollector)
}

// NewProcessStatCollector returns a new Collector exposing process data read from the proc filesystem.
func NewProcessStatCollector(logger log.Logger) (Collector, error) {
	fs, err := procfs.NewFS(*procPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}
	subsystem := "processes"
	return &processCollector{
		fs: fs,
		threadAlloc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "threads"),
			"Allocated threads in system",
			nil, nil,
		),
		threadLimit: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "max_threads"),
			"Limit of threads in the system",
			nil, nil,
		),
		threadsState: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "threads_state"),
			"Number of threads in each state.",
			[]string{"thread_state"}, nil,
		),
		procsState: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "state"),
			"Number of processes in each state.",
			[]string{"state"}, nil,
		),
		pidUsed: prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "pids"),
			"Number of PIDs", nil, nil,
		),
		pidMax: prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "max_processes"),
			"Number of max PIDs limit", nil, nil,
		),
		logger: logger,
	}, nil
}
func (c *processCollector) Update(ch chan<- prometheus.Metric) error {
	subsystem := "processes"
	pids, states, threads, threadStates, err := c.getAllocatedThreads()
	if err != nil {
		return fmt.Errorf("unable to retrieve number of allocated threads: %w", err)
	}

	ch <- prometheus.MustNewConstMetric(c.threadAlloc, prometheus.GaugeValue, float64(threads))
	maxThreads, err := readUintFromFile(procFilePath("sys/kernel/threads-max"))
	if err != nil {
		return fmt.Errorf("unable to retrieve limit number of threads: %w", err)
	}
	ch <- prometheus.MustNewConstMetric(c.threadLimit, prometheus.GaugeValue, float64(maxThreads))

	for state := range states {
		ch <- prometheus.MustNewConstMetric(c.procsState, prometheus.GaugeValue, float64(states[state]), state)
	}

	for state := range threadStates {
		ch <- prometheus.MustNewConstMetric(c.threadsState, prometheus.GaugeValue, float64(threadStates[state]), state)
	}

	pidM, err := readUintFromFile(procFilePath("sys/kernel/pid_max"))
	if err != nil {
		return fmt.Errorf("unable to retrieve limit number of maximum pids alloved: %w", err)
	}
	ch <- prometheus.MustNewConstMetric(c.pidUsed, prometheus.GaugeValue, float64(pids))
	ch <- prometheus.MustNewConstMetric(c.pidMax, prometheus.GaugeValue, float64(pidM))

	cpus, mems, rsss, ppids, commands, processthreads, err := c.getProcessInfo()
	if err == nil {
		for cpu := range cpus {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "cpu"),
					"Linux Process Cpu",
					[]string{"pid"}, nil,
				),
				prometheus.GaugeValue, cpus[cpu], cpu,
			)
		}
		for mem := range mems {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "mem"),
					"Linux Process Mem",
					[]string{"pid"}, nil,
				),
				prometheus.GaugeValue, mems[mem], mem,
			)
		}
		for rss := range rsss {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "rss"),
					"Linux Process Rss",
					[]string{"pid"}, nil,
				),
				prometheus.GaugeValue, rsss[rss], rss,
			)
		}
		for command := range commands {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "info"),
					"Linux Process info",
					[]string{"ppid", "pid", "command"}, nil,
				),
				prometheus.GaugeValue, 1, ppids[command], command, commands[command],
			)
			processthreads[command]++
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "thread_num"),
					"Linux Process threads",
					[]string{"pid"}, nil,
				),
				prometheus.GaugeValue, float64(processthreads[command]), command,
			)
		}
	}

	piddiskrds, piddiskwrs, piddiskcommands, err := c.getProcessDiskIO()
	if err == nil {
		for pidrd := range piddiskrds {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "disk_kb_read"),
					"Linux Process disk_kb_read",
					[]string{"pid", "command"}, nil,
				),
				prometheus.GaugeValue, piddiskrds[pidrd], pidrd, piddiskcommands[pidrd],
			)
		}
		for pidwr := range piddiskwrs {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "disk_kb_write"),
					"Linux Process disk_kb_write",
					[]string{"pid", "command"}, nil,
				),
				prometheus.GaugeValue, piddiskwrs[pidwr], pidwr, piddiskcommands[pidwr],
			)
		}
	}

	//pidiords, pidiowrs, pidiocommands, err := c.getProcessIO()
	//if err == nil {
	//	for pidrd := range pidiords {
	//		ch <- prometheus.MustNewConstMetric(
	//			prometheus.NewDesc(
	//				prometheus.BuildFQName(namespace, subsystem, "io_kb_read"),
	//				"Linux Process io_kb_read",
	//				[]string{"pid", "command"}, nil,
	//			),
	//			prometheus.GaugeValue, pidiords[pidrd], pidrd, pidiocommands[pidrd],
	//		)
	//	}
	//	for pidwr := range pidiowrs {
	//		ch <- prometheus.MustNewConstMetric(
	//			prometheus.NewDesc(
	//				prometheus.BuildFQName(namespace, subsystem, "io_kb_write"),
	//				"Linux Process io_kb_write",
	//				[]string{"pid", "command"}, nil,
	//			),
	//			prometheus.GaugeValue, pidiowrs[pidwr], pidwr, pidiocommands[pidwr],
	//		)
	//	}
	//}

	return nil
}

func (c *processCollector) getProcessInfo() (map[string]float64, map[string]float64, map[string]float64, map[string]string, map[string]string, map[string]int, error) {
	cpus := make(map[string]float64)
	mems := make(map[string]float64)
	rsss := make(map[string]float64)
	ppids := make(map[string]string)
	commands := make(map[string]string)
	threads := make(map[string]int)

	cmd := exec.Command("ps", "ax", "-o", "%cpu,%mem,rss,pid,ppid,command")

	// Run the command and capture the output
	output, err := cmd.Output()
	if err != nil {
		// Handle any errors that occurred while running the command
		level.Info(c.logger).Log("getProcessInfo Error", err)
		return nil, nil, nil, nil, nil, nil, err
	}

	result := strings.Split(strings.TrimSpace(string(output)), "\n")
	re := regexp.MustCompile(`\s+`)

	for _, s := range result[1:] {
		formatStr := re.ReplaceAllString(strings.TrimSpace(s), " ")
		str := strings.Split(formatStr, " ")
		Cpu, err := strconv.ParseFloat(str[0], 64)
		if err != nil {
			level.Info(c.logger).Log("Process Error", err)
			continue
		}

		Mem, err := strconv.ParseFloat(str[1], 64)
		if err != nil {
			level.Info(c.logger).Log("Process Error", err)
			continue
		}
		Rss, err := strconv.ParseFloat(str[2], 64)
		if err != nil {
			level.Info(c.logger).Log("Process Error", err)
			continue
		}
		Pid := str[3]
		Ppid := str[4]
		Commandline := strings.Join(str[5:], " ")
		cpus[Pid] = Cpu
		mems[Pid] = Mem
		rsss[Pid] = Rss
		ppids[Pid] = Ppid
		commands[Pid] = Commandline
		threads[Ppid]++
	}
	return cpus, mems, rsss, ppids, commands, threads, nil
}

func (c *processCollector) getProcessDiskIO() (map[string]float64, map[string]float64, map[string]string, error) {

	pidrds := make(map[string]float64)
	pidwrs := make(map[string]float64)
	pidcommands := make(map[string]string)

	cmd := exec.Command("pidstat", "-d", "-l", "1", "5")
	// Run the command and capture the output
	output, err := cmd.Output()
	if err != nil {
		level.Info(c.logger).Log("getProcessDiskIO Error", err)
		return nil, nil, nil, err
		// Handle any errors that occurred while running the command
	}
	result := strings.Split(strings.TrimSpace(string(output)), "\n")
	re := regexp.MustCompile(`\s+`)
	for _, s := range result {
		if strings.HasPrefix(s, "Average") && !strings.Contains(s, "kB_rd/s") {
			s = strings.TrimPrefix(s, "Average:")
			formatStr := re.ReplaceAllString(strings.TrimSpace(s), " ")
			str := strings.Split(formatStr, " ")

			pid := str[1]
			read_kb, err := strconv.ParseFloat(str[2], 64)
			if err != nil {
				level.Info(c.logger).Log("Process Error", err)
				continue
			}
			read_wr, err := strconv.ParseFloat(str[3], 64)
			if err != nil {
				level.Info(c.logger).Log("Process Error", err)
				continue
			}
			commands := strings.Join(str[5:], " ")
			pidrds[pid] = read_kb
			pidwrs[pid] = read_wr
			pidcommands[pid] = commands
		}
	}
	return pidrds, pidwrs, pidcommands, nil
}

func (c *processCollector) getProcessIO() (map[string]float64, map[string]float64, map[string]string, error) {
	pidrds := make(map[string]float64)
	pidwrs := make(map[string]float64)
	pidcommands := make(map[string]string)

	cmd := exec.Command("iotop", "-b", "-o", "-n", "1", "-k")
	// Run the command and capture the output
	output, err := cmd.Output()
	if err != nil {
		level.Info(c.logger).Log("getProcessIO Error", err)
		return nil, nil, nil, err
		// Handle any errors that occurred while running the command
	}
	result := strings.Split(strings.TrimSpace(string(output)), "\n")
	re := regexp.MustCompile(`\s+`)
	for _, s := range result[3:] {
		if strings.HasPrefix(s, "b'") {
			s = strings.TrimPrefix(s, "b'")
			s = strings.TrimSuffix(s, "'")
			formatStr := re.ReplaceAllString(strings.TrimSpace(s), " ")
			str := strings.Split(formatStr, " ")

			pid := str[0]
			read_kb, err := strconv.ParseFloat(str[3], 64)
			if err != nil {
				level.Info(c.logger).Log("Process Error", err)
				continue
			}
			read_wr, err := strconv.ParseFloat(str[5], 64)
			if err != nil {
				level.Info(c.logger).Log("Process Error", err)
				continue
			}
			commands := strings.Join(str[8:], " ")
			pidrds[pid] = read_kb
			pidwrs[pid] = read_wr
			pidcommands[pid] = commands

		} else {
			formatStr := re.ReplaceAllString(strings.TrimSpace(s), " ")
			str := strings.Split(formatStr, " ")

			pid := str[0]
			read_kb, err := strconv.ParseFloat(str[3], 64)
			if err != nil {
				level.Info(c.logger).Log("Process Error", err)
				continue
			}
			read_wr, err := strconv.ParseFloat(str[5], 64)
			if err != nil {
				level.Info(c.logger).Log("Process Error", err)
				continue
			}
			commands := strings.Join(str[11:], " ")
			pidrds[pid] = read_kb
			pidwrs[pid] = read_wr
			pidcommands[pid] = commands
		}

	}
	return pidrds, pidwrs, pidcommands, nil
}

func (c *processCollector) getAllocatedThreads() (int, map[string]int32, int, map[string]int32, error) {
	p, err := c.fs.AllProcs()
	if err != nil {
		return 0, nil, 0, nil, fmt.Errorf("unable to list all processes: %w", err)
	}
	pids := 0
	thread := 0
	procStates := make(map[string]int32)
	threadStates := make(map[string]int32)

	for _, pid := range p {
		stat, err := pid.Stat()
		if err != nil {
			// PIDs can vanish between getting the list and getting stats.
			if c.isIgnoredError(err) {
				level.Debug(c.logger).Log("msg", "file not found when retrieving stats for pid", "pid", pid.PID, "err", err)
				continue
			}
			level.Debug(c.logger).Log("msg", "error reading stat for pid", "pid", pid.PID, "err", err)
			return 0, nil, 0, nil, fmt.Errorf("error reading stat for pid %d: %w", pid.PID, err)
		}
		pids++
		procStates[stat.State]++
		thread += stat.NumThreads
		err = c.getThreadStates(pid.PID, stat, threadStates)
		if err != nil {
			return 0, nil, 0, nil, err
		}
	}
	return pids, procStates, thread, threadStates, nil
}

func (c *processCollector) getThreadStates(pid int, pidStat procfs.ProcStat, threadStates map[string]int32) error {
	fs, err := procfs.NewFS(procFilePath(path.Join(strconv.Itoa(pid), "task")))
	if err != nil {
		if c.isIgnoredError(err) {
			level.Debug(c.logger).Log("msg", "file not found when retrieving tasks for pid", "pid", pid, "err", err)
			return nil
		}
		level.Debug(c.logger).Log("msg", "error reading tasks for pid", "pid", pid, "err", err)
		return fmt.Errorf("error reading task for pid %d: %w", pid, err)
	}

	t, err := fs.AllProcs()
	if err != nil {
		if c.isIgnoredError(err) {
			level.Debug(c.logger).Log("msg", "file not found when retrieving tasks for pid", "pid", pid, "err", err)
			return nil
		}
		return fmt.Errorf("unable to list all threads for pid: %d %w", pid, err)
	}

	for _, thread := range t {
		if pid == thread.PID {
			threadStates[pidStat.State]++
			continue
		}
		threadStat, err := thread.Stat()
		if err != nil {
			if c.isIgnoredError(err) {
				level.Debug(c.logger).Log("msg", "file not found when retrieving stats for thread", "pid", pid, "threadId", thread.PID, "err", err)
				continue
			}
			level.Debug(c.logger).Log("msg", "error reading stat for thread", "pid", pid, "threadId", thread.PID, "err", err)
			return fmt.Errorf("error reading stat for pid:%d thread:%d err:%w", pid, thread.PID, err)
		}
		threadStates[threadStat.State]++
	}
	return nil
}

func (c *processCollector) isIgnoredError(err error) bool {
	if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), syscall.ESRCH.Error()) {
		return true
	}
	return false
}
