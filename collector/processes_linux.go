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
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"path/filepath"
	"io/ioutil"
	"sort"

	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

type ProcessFDInfo struct {
    PID     string
    Name    string
    FDCount int
    MaxFD   int
}

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

type processDiskIoInfo struct {
	piddiskrds      map[string]float64
	piddiskwrs      map[string]float64
	piddiskcommands map[string]string
}

// 定义数据库类型对应的进程名
var dbTypeToComm = map[string]string{
    "mysql": "mysqld",
    "redis": "redis-server",
    "mongo": "mongod",
}

func init() {
	registerCollector("processes", defaultEnabled, NewProcessStatCollector)
}

func splitStr(str string, start int) string {
	if len(str)-start < 2 || str[start] == ' ' { // 如果起始位置超过了字符串长度或者已经遇到了空格，则返回-1表示未找到
		return str
	}

	for i := start + 1; i < len(str); i++ {
		if strings.ContainsRune(" ", rune(str[i])) { // 判断当前字符是否为空格
			return str[0:i]
		}
	}

	// 若没有找到空格，则返回-1表示未找到
	return str
}

func ConvertMem(mem string) float64 {
	res := 0.0
	if strings.HasSuffix(mem, "g") {
		res, _ = strconv.ParseFloat(mem[:len(mem)-1], 64)
		res = res * 1024 * 1024
	} else if strings.HasSuffix(mem, "m") {
		res, _ = strconv.ParseFloat(mem[:len(mem)-1], 64)
		res = res * 1024
	} else {
		res, _ = strconv.ParseFloat(mem, 64)
	}
	return res
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

	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "version"),
			"Node Exporter Version",
			nil, nil,
		),
		prometheus.GaugeValue, 1.07,
	)

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
	
	// 自定义指标采集
	level.Debug(c.logger).Log("start self process collect")
	pidsqls, pidtypes, err := c.getDbPids()
	level.Debug(c.logger).Log("get db pids finished")

	cmd := exec.Command("top", "-n", "1", "-b", "-c", "-w", "512")
	output, err := cmd.Output()

	if err == nil {
		result := strings.Split(strings.TrimSpace(string(output)), "\n")
		re := regexp.MustCompile(`\s+`)
		re1 := regexp.MustCompile(`\d+`)
		matches := re1.FindAllString(result[1], -1)

		processs := make(map[string]float64)
		processs["total"], err = strconv.ParseFloat(matches[0], 64)
		processs["running"], err = strconv.ParseFloat(matches[1], 64)
		processs["sleeping"], err = strconv.ParseFloat(matches[2], 64)
		processs["stopped"], err = strconv.ParseFloat(matches[3], 64)
		processs["zombie"], err = strconv.ParseFloat(matches[4], 64)

		for process := range processs {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "task"),
					"Linux Process Task",
					[]string{"type"}, nil,
				),
				prometheus.GaugeValue, processs[process], process,
			)
		}
		for _, s := range result[7:] {
			formatStr := re.ReplaceAllString(strings.TrimSpace(s), " ")
			str := strings.Split(formatStr, " ")
			Cpu, err := strconv.ParseFloat(str[8], 64)
			if err != nil {
				return fmt.Errorf("unable to get cpu: %w", err)
			}
			Mem, err := strconv.ParseFloat(str[9], 64)
			// virt, err := strconv.ParseFloat(str[4], 64)
			virt := ConvertMem(str[4])
			res := ConvertMem(str[5])
			shr := ConvertMem(str[6])
			Pid := str[0]
			user := str[1]
			Commandline := strings.Join(str[11:], " ")
			Commandline = splitStr(Commandline, 100)

			//添加数据库进程的数据
			if val, ok := pidsqls[Pid]; ok {
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, subsystem, pidtypes[Pid]+"_cpu"),
						"Linux Process mysqld cpu",
						[]string{"pid", "dbname"}, nil,
					),
					prometheus.GaugeValue, Cpu, Pid, val,
				)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, subsystem, pidtypes[Pid]+"_mem"),
						"Linux Process mem",
						[]string{"pid", "dbname"}, nil,
					),
					prometheus.GaugeValue, Mem, Pid, val,
				)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, subsystem, pidtypes[Pid]+"_res"),
						"Linux Process res",
						[]string{"pid", "dbname"}, nil,
					),
					prometheus.GaugeValue, res, Pid, val,
				)
			}

			if Cpu > 0 {
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, subsystem, "cpu"),
						"Linux Process cpu",
						[]string{"pid", "command"}, nil,
					),
					prometheus.GaugeValue, Cpu, Pid, Commandline,
				)
			}
			if Mem > 0 {
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, subsystem, "mem"),
						"Linux Process mem",
						[]string{"pid", "command"}, nil,
					),
					prometheus.GaugeValue, Mem, Pid, Commandline,
				)
			}
			if virt > 0 {
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, subsystem, "virt"),
						"Linux Process virt",
						[]string{"pid", "command"}, nil,
					),
					prometheus.GaugeValue, virt, Pid, Commandline,
				)
			}
			if res > 0 {
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, subsystem, "res"),
						"Linux Process res",
						[]string{"pid", "command"}, nil,
					),
					prometheus.GaugeValue, res, Pid, Commandline,
				)
			}
			if shr > 0 {
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, subsystem, "shr"),
						"Linux Process shr",
						[]string{"pid", "command"}, nil,
					),
					prometheus.GaugeValue, shr, Pid, Commandline,
				)
			}
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "info"),
					"Linux Process info",
					[]string{"pid", "command", "user"}, nil,
				),
				prometheus.GaugeValue, 1, Pid, Commandline, user,
			)
		}
	}
	level.Debug(c.logger).Log("get top metrics finished")
	processes, err := listProcesses()
	sort.Slice(processes, func(i, j int) bool {
        return processes[i].FDCount > processes[j].FDCount
    })
    topN := 100
    if len(processes) < topN {
        topN = len(processes)
    }
    topProcesses := processes[:topN]
    for _, p := range topProcesses {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, subsystem, "fd_open"),
				"Linux Process info",
				[]string{"pid", "command"}, nil,
			),
			prometheus.GaugeValue, float64(p.FDCount), p.PID, p.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, subsystem, "fd_max"),
				"Linux Process info",
				[]string{"pid", "command"}, nil,
			),
			prometheus.GaugeValue, float64(p.MaxFD), p.PID, p.Name,
		)
    }
	level.Debug(c.logger).Log("get fd metrics finished")
	info, err := c.getProcessDiskIO()
	if err == nil {
		for pidrd := range info.piddiskrds {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "disk_kb_read"),
					"Linux Process disk_kb_read",
					[]string{"pid", "command"}, nil,
				),
				prometheus.GaugeValue, info.piddiskrds[pidrd], pidrd, info.piddiskcommands[pidrd],
			)
		}
		for pidwr := range info.piddiskwrs {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "disk_kb_write"),
					"Linux Process disk_kb_write",
					[]string{"pid", "command"}, nil,
				),
				prometheus.GaugeValue, info.piddiskwrs[pidwr], pidwr, info.piddiskcommands[pidwr],
			)
		}
	}
	level.Debug(c.logger).Log("get disk io metrics finished")
	//获取端口占用
	cmd = exec.Command("ss", "-tulnp")
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("ss command error: %w", err)
	}
	outputStr := string(output)
	scanner := bufio.NewScanner(strings.NewReader(outputStr))
	var results []string

	for scanner.Scan() {
		line := scanner.Text()
		results = append(results, strings.TrimSpace(line))
	}
	
	// 生成指标
	for _, result := range results[1:] {
		values := strings.Fields(result)
		if len(values) < 7 {
			continue
		}
		net_type := values[0]
		state := values[1]
		ip := strings.Split(values[4], ":")
		local_port := ip[len(ip)-1]
		re := regexp.MustCompile(`\("([^"]+)",pid=(\d+),fd=(\d+)\)`)
		// 查找所有匹配项
		matches := re.FindAllStringSubmatch(values[6], -1)
		for _, match := range matches {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, "port_occupied"),
					"Linux Process port occupied",
					[]string{"type", "state", "port", "process", "pid", "fd"}, nil,
				),
				prometheus.GaugeValue, 1, net_type, state, local_port, match[1], match[2], match[3],
			)
		}
	}
	level.Debug(c.logger).Log("get port occupied metrics finished。")
	return nil
}

func (c *processCollector) getProcessDiskIO() (*processDiskIoInfo, error) {
	pidrds := make(map[string]float64)
	pidwrs := make(map[string]float64)
	pidcommands := make(map[string]string)

	cmd := exec.Command("pidstat", "-d", "-l", "1", "1")
	// Run the command and capture the output
	output, err := cmd.Output()
	if err != nil {
		level.Info(c.logger).Log("getProcessDiskIO Error", err)
		return nil, err
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
	info := &processDiskIoInfo{
		piddiskrds:      pidrds,
		piddiskwrs:      pidwrs,
		piddiskcommands: pidcommands,
	}
	return info, nil
}

func (c *processCollector) getDbPids() (map[string]string, map[string]string, error) {
	pidmysqls := make(map[string]string)
	pidtypes := make(map[string]string)
	currentTime := time.Now()
	timestamp := currentTime.UnixNano()
	level.Debug(c.logger).Log("start get db。",timestamp)
	cmd := exec.Command("docker", "ps", "-a", "-q", "--filter", "status=running", "--filter", "name=k8s_mysql_", "--filter", "name=k8s_redis_", "--filter", "name=k8s_mongo_")
	currentTime = time.Now()
	timestamp = currentTime.UnixNano()
	level.Debug(c.logger).Log("get docker container id finished。",timestamp)
	output, err := cmd.Output()
	if err == nil {
		result := strings.Split(strings.TrimSpace(string(output)), "\n")
		str := []string{
			"docker",
			"inspect",
			"-f",
			"{{.State.Pid}} {{index .Config.Labels \"io.kubernetes.pod.name\"}} {{index .Config.Labels \"io.kubernetes.container.name\"}}",
		}
		for _, s := range result {
			str = append(str, s)
		}
		cmd = exec.Command(str[0], str[1:]...)
		output, err = cmd.Output()
		if err == nil {
			strs := strings.Split(strings.TrimSpace(string(output)), "\n")
			for _, str := range strs {
				lists := strings.Split(str, " ")
				pid := lists[0]
				dbname := ""
				dbtype := lists[2]

				index := strings.Index(lists[1], "-deploy")
				if index != -1 {
					dbname = lists[1][:index]
				} else {
					dbname = lists[1]
				}
				
				// 处理进程树
				if targetComm, ok := dbTypeToComm[dbtype]; ok {
					if newPid, err := findChildProcess(pid, targetComm); err == nil {
						pid = newPid
					}
				}
				pidmysqls[pid] = dbname
				pidtypes[pid] = dbtype

			}
		}
		currentTime = time.Now()
		timestamp = currentTime.UnixNano()
		level.Debug(c.logger).Log("get db pid finished。",timestamp)
		return pidmysqls, pidtypes, nil
	}
	return nil, nil, nil
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

// 通过/proc文件系统查找子进程
func findChildProcess(parentPid string, targetComm string) (string, error) {
    ppid, err := strconv.Atoi(parentPid)
    if err != nil {
        return parentPid, err
    }

    return findRecursive(ppid, targetComm, 0)
}

// 递归查找子进程（最大深度3层）
func findRecursive(pid int, target string, depth int) (string, error) {
    if depth > 3 {
        return "", fmt.Errorf("max depth exceeded")
    }

    children, err := getChildrenPIDs(pid)
    if err != nil {
        return "", err
    }

    for _, child := range children {
        comm, _ := getProcessComm(child)
        if comm == target {
            return strconv.Itoa(child), nil
        }

        if found, err := findRecursive(child, target, depth+1); err == nil {
            return found, nil
        }
    }

    return "", fmt.Errorf("target process not found")
}

// 获取进程的子进程ID列表
func getChildrenPIDs(pid int) ([]int, error) {
    data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(pid), "children"))
    if err != nil {
        return nil, err
    }

    var pids []int
    for _, s := range strings.Fields(string(data)) {
        pid, _ := strconv.Atoi(s)
        if pid > 0 {
            pids = append(pids, pid)
        }
    }
    return pids, nil
}

// 获取进程名称
func getProcessComm(pid int) (string, error) {
    data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(string(data)), nil
}

func listProcesses() ([]ProcessFDInfo, error) {
    var processes []ProcessFDInfo

    files, err := ioutil.ReadDir("/proc")
    if err != nil {
        return nil, fmt.Errorf("failed to read /proc: %w", err)
    }

    for _, file := range files {
        if !file.IsDir() {
            continue
        }

        pid, err := strconv.Atoi(file.Name())
        if err != nil {
            continue // 跳过非进程目录
        }

        name, err := getProcessComm(pid)
        if err != nil {
            continue
        }

        fdCount := countOpenFiles(pid)
        if fdCount == 0 {
            continue
        }

        maxFD := getMaxFD(pid)

        processes = append(processes, ProcessFDInfo{
            PID:     strconv.Itoa(pid),
            Name:    name,
            FDCount: fdCount,
            MaxFD:   maxFD,
        })
    }

    return processes, nil
}

func countOpenFiles(pid int) int {
    fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
    files, err := ioutil.ReadDir(fdDir)
    if err != nil {
        return 0
    }
    return len(files)
}

func getMaxFD(pid int) int {
    limitsPath := filepath.Join("/proc", strconv.Itoa(pid), "limits")
    data, err := ioutil.ReadFile(limitsPath)
    if err != nil {
        return 1024
    }

    lines := strings.Split(string(data), "\n")
    for _, line := range lines {
        if strings.Contains(line, "Max open files") {
            fields := strings.Fields(line)
            if len(fields) >= 4 {
				MaxFD, err := strconv.Atoi(fields[3])
				if err != nil {
					return 1024
				}
                return MaxFD
            }
        }
    }
    return 1024
}
