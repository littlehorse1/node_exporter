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
	"container/heap"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

// =============================================================================
// 【优化1】包级正则变量：只编译一次，避免每次 Update 调用重复编译
// =============================================================================

var (
	// rePortProc 匹配 ss 输出中的进程信息，格式：("name",pid=1234,fd=5)
	rePortProc = regexp.MustCompile(`\("([^"]+)",pid=(\d+),fd=(\d+)\)`)
)

// =============================================================================
// 【优化2】NVML 全局单例：进程生命周期内只初始化一次
// 消除了原先每次采集都调用 nvidia-smi 子进程 + NVML 双重 Init/Shutdown 的问题
// =============================================================================

var (
	nvmlOnce      sync.Once
	nvmlAvailable bool
)

func initNVML() {
	nvmlOnce.Do(func() {
		if ret := nvml.Init(); ret != nvml.SUCCESS {
			return
		}
		count, ret := nvml.DeviceGetCount()
		if ret != nvml.SUCCESS || count == 0 {
			nvml.Shutdown()
			return
		}
		nvmlAvailable = true
		// 保持 NVML 常驻，不在此 Shutdown——Prometheus 采集器无显式停止钩子
	})
}

// =============================================================================
// 【优化3】UID → 用户名缓存：避免对每个进程都查询 /etc/passwd
// =============================================================================

var (
	uidNameCache   = map[uint32]string{}
	uidNameCacheMu sync.RWMutex
)

func lookupUsername(uid uint32) string {
	uidNameCacheMu.RLock()
	if name, ok := uidNameCache[uid]; ok {
		uidNameCacheMu.RUnlock()
		return name
	}
	uidNameCacheMu.RUnlock()

	name := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	uidNameCacheMu.Lock()
	uidNameCache[uid] = name
	uidNameCacheMu.Unlock()
	return name
}

// =============================================================================
// 类型定义
// =============================================================================

type GPU struct {
	Name              string
	Uuid              string
	GpuUtilization    float64
	MemoryUtilization float64
	MemoryTotal       float64
	MemoryUsed        float64
	MemoryFree        float64
	Temperature       float64
}

type ProcessFDInfo struct {
	PID     string
	Name    string
	FDCount int
	MaxFD   int
}

// 【优化4】fdMinHeap：用 O(n·log k) 最小堆维护 Top-K 进程，替代全量 sort.Slice O(n·log n)
type fdMinHeap []ProcessFDInfo

func (h fdMinHeap) Len() int            { return len(h) }
func (h fdMinHeap) Less(i, j int) bool  { return h[i].FDCount < h[j].FDCount }
func (h fdMinHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *fdMinHeap) Push(x interface{}) { *h = append(*h, x.(ProcessFDInfo)) }
func (h *fdMinHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// ioSnapshot 记录单个进程的磁盘 IO 快照（用于跨采集周期计算速率）
type ioSnapshot struct {
	readBytes  uint64
	writeBytes uint64
}

// cpuSnapshot 记录单个进程的 CPU jiffies 快照（用于跨采集周期计算 CPU%）
type cpuSnapshot struct {
	jiffies uint64 // utime + stime 总时钟滴答数
}

// perProcMetrics 存储单个进程在一次 /proc 扫描中采集到的所有指标
type perProcMetrics struct {
	pid     int
	comm    string  // 进程短名（来自 /proc/<pid>/stat 括号内）
	user    string
	cmdline string  // 完整命令行，截断到 100 字符后首个空格处
	cpuPct  float64 // CPU 使用率百分比（跨周期差分）
	memPct  float64 // 内存使用率百分比
	virtKB  float64 // 虚拟内存 KB
	resKB   float64 // 常驻内存 KB
	shrKB   float64 // 共享内存 KB
}

// procScanResult 是单次 /proc 全量扫描的汇总结果
type procScanResult struct {
	perProc      []perProcMetrics
	topFDs       []ProcessFDInfo    // FD 最多的 Top-100 进程（降序）
	diskReadKBs  map[string]float64 // pidStr → 读速率 KB/s
	diskWriteKBs map[string]float64 // pidStr → 写速率 KB/s
	diskComm     map[string]string  // pidStr → comm（用于标签）
}

// 【优化5】processCollector：所有 prometheus.Desc 在构造时预创建，消除热路径中的重复分配
type processCollector struct {
	fs           procfs.FS
	// 原生线程/进程指标（与原始代码保持一致）
	threadAlloc  *prometheus.Desc
	threadLimit  *prometheus.Desc
	threadsState *prometheus.Desc
	procsState   *prometheus.Desc
	pidUsed      *prometheus.Desc
	pidMax       *prometheus.Desc
	// 自定义指标描述符（预创建，不在 Update 热路径中 NewDesc）
	descVersion   *prometheus.Desc
	descTask      *prometheus.Desc
	descDbCPU     map[string]*prometheus.Desc // dbtype → desc，如 mysql_cpu / redis_cpu
	descDbMem     map[string]*prometheus.Desc
	descDbRes     map[string]*prometheus.Desc
	descCPU       *prometheus.Desc
	descMem       *prometheus.Desc
	descVirt      *prometheus.Desc
	descRes       *prometheus.Desc
	descShr       *prometheus.Desc
	descInfo      *prometheus.Desc
	descFdOpen    *prometheus.Desc
	descFdMax     *prometheus.Desc
	descDiskRead  *prometheus.Desc
	descDiskWrite *prometheus.Desc
	descPort      *prometheus.Desc
	// GPU 指标描述符
	descGpuUtil     *prometheus.Desc
	descGpuMemUtil  *prometheus.Desc
	descGpuMemTotal *prometheus.Desc
	descGpuMemUsed  *prometheus.Desc
	descGpuMemFree  *prometheus.Desc
	descGpuTemp     *prometheus.Desc

	// 跨采集周期状态（需持锁访问），用于计算 CPU% 和磁盘 IO 速率
	statsMu     sync.Mutex
	prevIOStats map[int]ioSnapshot
	prevCPUStat map[int]cpuSnapshot
	prevTime    time.Time

	logger log.Logger
}

// 数据库类型 → 进程 comm 名称映射
var dbTypeToComm = map[string]string{
	"mysql": "mysqld",
	"redis": "redis-server",
	"mongo": "mongod",
}

// clkTck 是 Linux 时钟滴答频率（USER_HZ），绝大多数 Linux 系统固定为 100
const clkTck = 100

func init() {
	registerCollector("processes", defaultEnabled, NewProcessStatCollector)
}

// =============================================================================
// 工具函数
// =============================================================================

// truncateAtSpace 截断字符串，在 start 位置之后第一个空格处结束。
// 原 splitStr 命名混乱，且用 strings.ContainsRune 判断单个空格字符过于绕圈，此处简化重命名。
func truncateAtSpace(str string, start int) string {
	if start >= len(str) {
		return str
	}
	for i := start + 1; i < len(str); i++ {
		if str[i] == ' ' {
			return str[:i]
		}
	}
	return str
}

// ConvertMem 将带后缀的内存字符串（k/m/g，大小写均可）转换为 KB。
// 【修复】原版缺少 'k' 单位：top 有时输出 "512k" 格式，缺失时 ParseFloat 失败返回 0。
func ConvertMem(mem string) float64 {
	if len(mem) == 0 {
		return 0
	}
	suffix := mem[len(mem)-1]
	numStr := mem[:len(mem)-1]
	switch suffix {
	case 'g', 'G':
		v, _ := strconv.ParseFloat(numStr, 64)
		return v * 1024 * 1024
	case 'm', 'M':
		v, _ := strconv.ParseFloat(numStr, 64)
		return v * 1024
	case 'k', 'K':
		v, _ := strconv.ParseFloat(numStr, 64)
		return v
	default:
		v, _ := strconv.ParseFloat(mem, 64)
		return v
	}
}

// getMemTotalKB 从 /proc/meminfo 读取系统总内存（单位 KB），用于计算各进程 MEM%
func getMemTotalKB() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			if fields := strings.Fields(line); len(fields) >= 2 {
				v, _ := strconv.ParseFloat(fields[1], 64)
				return v // /proc/meminfo 单位已是 kB
			}
		}
	}
	return 0
}

// countFDsByDir 统计 fdDir 目录中的条目数量（即进程打开的 FD 数量）。
// 【优化】用 Readdirnames 只加载文件名，避免 ioutil.ReadDir 构造完整 FileInfo 切片的开销。
func countFDsByDir(fdDir string) int {
	f, err := os.Open(fdDir)
	if err != nil {
		return 0
	}
	defer f.Close()
	names, _ := f.Readdirnames(-1)
	return len(names)
}

// getMaxFD 从 /proc/<pid>/limits 读取进程的最大文件描述符限制
func getMaxFD(pid int) int {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "limits"))
	if err != nil {
		return 1024
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "Max open files") {
			if fields := strings.Fields(line); len(fields) >= 4 {
				if v, err := strconv.Atoi(fields[3]); err == nil {
					return v
				}
			}
		}
	}
	return 1024
}

// =============================================================================
// GPU 采集（基于 NVML 单例，不再每次调用 nvidia-smi 子进程）
// =============================================================================

// getGPUInfo 通过 NVML 获取所有 GPU 的实时指标。
// 【修复】原版每次采集都执行 nvidia-smi --help 子进程，且 isNvidiaSMIInstalled 与 getGPUInfo
// 之间 nvml.Init 被调用两次但只 Shutdown 一次，导致资源泄漏。现统一由 sync.Once 管理。
func getGPUInfo() ([]GPU, error) {
	initNVML()
	if !nvmlAvailable {
		return nil, nil // 无 GPU 或初始化失败，静默跳过，不打印 fmt.Println
	}
	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("获取 GPU 数量失败: %s", nvml.ErrorString(ret))
	}
	var gpus []GPU
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			continue
		}
		g := GPU{}
		if name, ret := device.GetName(); ret == nvml.SUCCESS {
			g.Name = name
		}
		if uuid, ret := device.GetUUID(); ret == nvml.SUCCESS {
			g.Uuid = uuid
		}
		if util, ret := device.GetUtilizationRates(); ret == nvml.SUCCESS {
			g.GpuUtilization = float64(util.Gpu)
			g.MemoryUtilization = float64(util.Memory)
		}
		if mem, ret := device.GetMemoryInfo(); ret == nvml.SUCCESS {
			g.MemoryTotal = float64(mem.Total)
			g.MemoryUsed = float64(mem.Used)
			g.MemoryFree = float64(mem.Free)
		}
		if temp, ret := device.GetTemperature(nvml.TEMPERATURE_GPU); ret == nvml.SUCCESS {
			g.Temperature = float64(temp)
		}
		gpus = append(gpus, g)
	}
	return gpus, nil
}

// =============================================================================
// 采集器构造：所有 prometheus.Desc 在此一次性预创建
// =============================================================================

func NewProcessStatCollector(logger log.Logger) (Collector, error) {
	fs, err := procfs.NewFS(*procPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}
	sub := "processes"

	// 为每种数据库类型预创建专项指标描述符
	dbCPU := make(map[string]*prometheus.Desc)
	dbMem := make(map[string]*prometheus.Desc)
	dbRes := make(map[string]*prometheus.Desc)
	for dbtype := range dbTypeToComm {
		dbCPU[dbtype] = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, dbtype+"_cpu"),
			"Linux Process "+dbtype+" cpu percent",
			[]string{"pid", "dbname"}, nil,
		)
		dbMem[dbtype] = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, dbtype+"_mem"),
			"Linux Process "+dbtype+" memory percent",
			[]string{"pid", "dbname"}, nil,
		)
		dbRes[dbtype] = prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, dbtype+"_res"),
			"Linux Process "+dbtype+" resident memory KB",
			[]string{"pid", "dbname"}, nil,
		)
	}

	// 异步预热 NVML，不阻塞采集器创建（第一次采集时必然已完成初始化）
	go initNVML()

	return &processCollector{
		fs: fs,
		threadAlloc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "threads"),
			"Allocated threads in system", nil, nil,
		),
		threadLimit: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "max_threads"),
			"Limit of threads in the system", nil, nil,
		),
		threadsState: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "threads_state"),
			"Number of threads in each state.",
			[]string{"thread_state"}, nil,
		),
		procsState: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "state"),
			"Number of processes in each state.",
			[]string{"state"}, nil,
		),
		pidUsed: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "pids"),
			"Number of PIDs", nil, nil,
		),
		pidMax: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "max_processes"),
			"Number of max PIDs limit", nil, nil,
		),
		descVersion: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "version"),
			"Node Exporter Version", nil, nil,
		),
		descTask: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "task"),
			"Linux process task counts by type",
			[]string{"type"}, nil,
		),
		descDbCPU: dbCPU,
		descDbMem: dbMem,
		descDbRes: dbRes,
		descCPU: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "cpu"),
			"Linux Process cpu percent",
			[]string{"pid", "command"}, nil,
		),
		descMem: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "mem"),
			"Linux Process memory percent",
			[]string{"pid", "command"}, nil,
		),
		descVirt: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "virt"),
			"Linux Process virtual memory KB",
			[]string{"pid", "command"}, nil,
		),
		descRes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "res"),
			"Linux Process resident memory KB",
			[]string{"pid", "command"}, nil,
		),
		descShr: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "shr"),
			"Linux Process shared memory KB",
			[]string{"pid", "command"}, nil,
		),
		descInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "info"),
			"Linux Process info",
			[]string{"pid", "command", "user"}, nil,
		),
		descFdOpen: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "fd_open"),
			"Linux Process open file descriptor count",
			[]string{"pid", "command"}, nil,
		),
		descFdMax: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "fd_max"),
			"Linux Process max file descriptor limit",
			[]string{"pid", "command"}, nil,
		),
		descDiskRead: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "disk_kb_read"),
			"Linux Process disk read KB/s",
			[]string{"pid", "command"}, nil,
		),
		descDiskWrite: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "disk_kb_write"),
			"Linux Process disk write KB/s",
			[]string{"pid", "command"}, nil,
		),
		descPort: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, sub, "port_occupied"),
			"Linux Process port occupied",
			[]string{"type", "state", "port", "process", "pid", "fd"}, nil,
		),
		descGpuUtil: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "gpu", "utilization"),
			"Linux Gpu Utilization",
			[]string{"name", "uuid"}, nil,
		),
		descGpuMemUtil: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "gpu", "memory_utilization"),
			"Linux Gpu Memory Utilization",
			[]string{"name", "uuid"}, nil,
		),
		descGpuMemTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "gpu", "memory_total"),
			"Linux Gpu memory total",
			[]string{"name", "uuid"}, nil,
		),
		descGpuMemUsed: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "gpu", "memory_used"),
			"Linux Gpu memory used",
			[]string{"name", "uuid"}, nil,
		),
		descGpuMemFree: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "gpu", "memory_free"),
			"Linux Gpu Memory free",
			[]string{"name", "uuid"}, nil,
		),
		descGpuTemp: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "gpu", "temperature"),
			"Linux Gpu temperature",
			[]string{"name", "uuid"}, nil,
		),
		prevIOStats: make(map[int]ioSnapshot),
		prevCPUStat: make(map[int]cpuSnapshot),
		logger:      logger,
	}, nil
}

// =============================================================================
// Update：主采集入口
// =============================================================================

func (c *processCollector) Update(ch chan<- prometheus.Metric) error {
	// ── 顶层超时：整个 Update 不得超过 14s（留 1s 余量给指标写出）────────────
	// 所有子任务（goroutine 或同步调用）均从此 ctx 派生，确保硬性上限。
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()

	ch <- prometheus.MustNewConstMetric(c.descVersion, prometheus.GaugeValue, 1.08)

	// ── 原生线程/进程统计（保持不变）────────────────────────────────────────
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

	for state, cnt := range states {
		ch <- prometheus.MustNewConstMetric(c.procsState, prometheus.GaugeValue, float64(cnt), state)
	}
	for state, cnt := range threadStates {
		ch <- prometheus.MustNewConstMetric(c.threadsState, prometheus.GaugeValue, float64(cnt), state)
	}

	pidM, err := readUintFromFile(procFilePath("sys/kernel/pid_max"))
	if err != nil {
		return fmt.Errorf("unable to retrieve limit number of maximum pids alloved: %w", err)
	}
	ch <- prometheus.MustNewConstMetric(c.pidUsed, prometheus.GaugeValue, float64(pids))
	ch <- prometheus.MustNewConstMetric(c.pidMax, prometheus.GaugeValue, float64(pidM))

	// ── 任务统计（从 states 聚合，替代原先解析 top Tasks 行）────────────────
	// states 的 key 为 /proc/<pid>/stat 中的单字符状态（R/S/D/T/Z/I/t 等）
	var taskTotal int32
	for _, cnt := range states {
		taskTotal += cnt
	}
	taskCounts := map[string]int32{
		"total":    taskTotal,
		"running":  states["R"],
		"sleeping": states["S"] + states["D"] + states["I"],
		"stopped":  states["T"] + states["t"],
		"zombie":   states["Z"],
	}
	for t, v := range taskCounts {
		ch <- prometheus.MustNewConstMetric(c.descTask, prometheus.GaugeValue, float64(v), t)
	}

	// ── 【优化6】并行采集：DB PID、端口、GPU（外部命令/API，与 /proc 扫描无共享状态）──
	type dbResult struct {
		pidsqls map[string]string
		pidtypes map[string]string
		err     error
	}
	type ssResult struct {
		lines []string
		err   error
	}
	type gpuResult struct {
		gpus []GPU
		err  error
	}
	dbCh  := make(chan dbResult, 1)
	ssCh  := make(chan ssResult, 1)
	gpuCh := make(chan gpuResult, 1)

	go func() {
		// getDbPids 内部再派生 10s 子 ctx，实际超时 = min(父剩余, 10s)
		p, t, e := c.getDbPids(ctx)
		dbCh <- dbResult{p, t, e}
	}()
	go func() {
		// runSS 内部再派生 5s 子 ctx，实际超时 = min(父剩余, 5s)
		lines, e := runSS(ctx)
		ssCh <- ssResult{lines, e}
	}()
	go func() {
		// NVML 不支持 context，用 select 确保不超出顶层 ctx 期限
		// 内层 goroutine 写入 buffered channel，即使已超时也不会泄漏
		inner := make(chan gpuResult, 1)
		go func() {
			gpus, e := getGPUInfo()
			inner <- gpuResult{gpus, e}
		}()
		select {
		case r := <-inner:
			gpuCh <- r
		case <-ctx.Done():
			// 超时或被取消：静默跳过 GPU 指标，不阻塞 Update 返回
			gpuCh <- gpuResult{nil, nil}
		}
	}()

	// ── 主路径：一次遍历 /proc，合并完成 CPU%、内存、FD、磁盘 IO 采集 ───────
	level.Debug(c.logger).Log("msg", "start proc scan")
	procData, scanErr := c.scanAllProcs()
	level.Debug(c.logger).Log("msg", "proc scan finished")

	// 等待 DB PID 结果（已在 proc 扫描期间并行运行完毕）
	dbRes := <-dbCh
	// 【修复】原版 err 被下一行赋值静默覆盖，此处改用独立变量
	if dbRes.err != nil {
		level.Debug(c.logger).Log("msg", "getDbPids error", "err", dbRes.err)
	}
	pidsqls := dbRes.pidsqls
	pidtypes := dbRes.pidtypes
	if pidsqls == nil {
		pidsqls = map[string]string{}
		pidtypes = map[string]string{}
	}

	if scanErr == nil {
		for _, pd := range procData.perProc {
			pidStr := strconv.Itoa(pd.pid)

			// 数据库进程专项指标
			if dbname, ok := pidsqls[pidStr]; ok {
				dbtype := pidtypes[pidStr]
				if desc, ok2 := c.descDbCPU[dbtype]; ok2 {
					ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, pd.cpuPct, pidStr, dbname)
				}
				if desc, ok2 := c.descDbMem[dbtype]; ok2 {
					ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, pd.memPct, pidStr, dbname)
				}
				if desc, ok2 := c.descDbRes[dbtype]; ok2 {
					ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, pd.resKB, pidStr, dbname)
				}
			}

			if pd.cpuPct > 0 {
				ch <- prometheus.MustNewConstMetric(c.descCPU, prometheus.GaugeValue, pd.cpuPct, pidStr, pd.cmdline)
			}
			if pd.memPct > 0 {
				ch <- prometheus.MustNewConstMetric(c.descMem, prometheus.GaugeValue, pd.memPct, pidStr, pd.cmdline)
			}
			if pd.virtKB > 0 {
				ch <- prometheus.MustNewConstMetric(c.descVirt, prometheus.GaugeValue, pd.virtKB, pidStr, pd.cmdline)
			}
			if pd.resKB > 0 {
				ch <- prometheus.MustNewConstMetric(c.descRes, prometheus.GaugeValue, pd.resKB, pidStr, pd.cmdline)
			}
			if pd.shrKB > 0 {
				ch <- prometheus.MustNewConstMetric(c.descShr, prometheus.GaugeValue, pd.shrKB, pidStr, pd.cmdline)
			}
			ch <- prometheus.MustNewConstMetric(c.descInfo, prometheus.GaugeValue, 1, pidStr, pd.cmdline, pd.user)
		}

		// FD Top-100（已由堆排序，降序排列）
		for _, fd := range procData.topFDs {
			ch <- prometheus.MustNewConstMetric(c.descFdOpen, prometheus.GaugeValue, float64(fd.FDCount), fd.PID, fd.Name)
			ch <- prometheus.MustNewConstMetric(c.descFdMax, prometheus.GaugeValue, float64(fd.MaxFD), fd.PID, fd.Name)
		}

		// 磁盘 IO 速率（跨采集周期差分计算，第一次采集无历史数据属正常，不输出）
		for pidStr, readKBs := range procData.diskReadKBs {
			ch <- prometheus.MustNewConstMetric(c.descDiskRead, prometheus.GaugeValue, readKBs, pidStr, procData.diskComm[pidStr])
		}
		for pidStr, writeKBs := range procData.diskWriteKBs {
			ch <- prometheus.MustNewConstMetric(c.descDiskWrite, prometheus.GaugeValue, writeKBs, pidStr, procData.diskComm[pidStr])
		}
	} else {
		level.Warn(c.logger).Log("msg", "proc scan failed", "err", scanErr)
	}
	level.Debug(c.logger).Log("msg", "proc metrics emitted")

	// ── 端口占用（等待 ss 结果）────────────────────────────────────────────
	ssRes := <-ssCh
	if ssRes.err != nil {
		return fmt.Errorf("ss command error: %w", ssRes.err)
	}
	if len(ssRes.lines) > 1 {
		for _, line := range ssRes.lines[1:] {
			values := strings.Fields(line)
			if len(values) < 7 {
				continue
			}
			netType  := values[0]
			ssState  := values[1]
			ipParts  := strings.Split(values[4], ":")
			localPort := ipParts[len(ipParts)-1]
			// 【优化】rePortProc 已提升为包级变量，此处直接使用
			for _, m := range rePortProc.FindAllStringSubmatch(values[6], -1) {
				ch <- prometheus.MustNewConstMetric(
					c.descPort, prometheus.GaugeValue, 1,
					netType, ssState, localPort, m[1], m[2], m[3],
				)
			}
		}
	}
	level.Debug(c.logger).Log("msg", "port metrics emitted")

	// ── GPU（等待结果）──────────────────────────────────────────────────────
	gpuRes := <-gpuCh
	if gpuRes.err == nil {
		for _, gpu := range gpuRes.gpus {
			ch <- prometheus.MustNewConstMetric(c.descGpuUtil, prometheus.GaugeValue, gpu.GpuUtilization, gpu.Name, gpu.Uuid)
			ch <- prometheus.MustNewConstMetric(c.descGpuMemUtil, prometheus.GaugeValue, gpu.MemoryUtilization, gpu.Name, gpu.Uuid)
			ch <- prometheus.MustNewConstMetric(c.descGpuMemTotal, prometheus.GaugeValue, gpu.MemoryTotal, gpu.Name, gpu.Uuid)
			ch <- prometheus.MustNewConstMetric(c.descGpuMemUsed, prometheus.GaugeValue, gpu.MemoryUsed, gpu.Name, gpu.Uuid)
			ch <- prometheus.MustNewConstMetric(c.descGpuMemFree, prometheus.GaugeValue, gpu.MemoryFree, gpu.Name, gpu.Uuid)
			ch <- prometheus.MustNewConstMetric(c.descGpuTemp, prometheus.GaugeValue, gpu.Temperature, gpu.Name, gpu.Uuid)
		}
	}
	level.Debug(c.logger).Log("msg", "gpu metrics emitted")

	return nil
}

// =============================================================================
// scanAllProcs：一次遍历 /proc，合并替代原先三个独立调用：
//   1. top -n 1 -b -c -w 512（子进程，每次有 fork 开销）
//   2. listProcesses（读 /proc/*/fd、/proc/*/comm、/proc/*/limits）
//   3. pidstat -d -l 1 1（子进程，每次强制等待 ≥1 秒！）
// =============================================================================

func (c *processCollector) scanAllProcs() (*procScanResult, error) {
	now        := time.Now()
	pageKB     := float64(os.Getpagesize()) / 1024.0
	memTotalKB := getMemTotalKB()

	// 读取上一周期快照（持锁保护，读完即释放锁）
	c.statsMu.Lock()
	prevIO   := c.prevIOStats
	prevCPU  := c.prevCPUStat
	prevTime := c.prevTime
	c.statsMu.Unlock()

	elapsed  := now.Sub(prevTime).Seconds()
	firstRun := prevTime.IsZero() // 首次采集无历史数据，CPU% 和磁盘速率为 0

	newIO  := make(map[int]ioSnapshot,  len(prevIO))
	newCPU := make(map[int]cpuSnapshot, len(prevCPU))

	// FD Top-100 最小堆（堆顶为当前 Top-100 中 FDCount 最小者）
	const topK = 100
	h := &fdMinHeap{}
	heap.Init(h)

	result := &procScanResult{

		diskReadKBs:  make(map[string]float64),
		diskWriteKBs: make(map[string]float64),
		diskComm:     make(map[string]string),
	}

	// 用 os.ReadDir 替代已废弃的 ioutil.ReadDir
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // 跳过 /proc/net、/proc/sys 等非进程目录
		}
		pidStr  := entry.Name()
		procDir := "/proc/" + pidStr

		// ── /proc/<pid>/stat：comm、CPU jiffies、虚拟内存、RSS ─────────────
		statData, err := os.ReadFile(procDir + "/stat")
		if err != nil {
			continue // 进程可能已在扫描过程中退出，跳过
		}
		statStr := string(statData)

		// comm 包在括号内且可能含空格，必须用 LastIndex 定位右括号
		// 格式：<pid> (<comm>) <state> <ppid> ... <utime> <stime> ... <vsize> <rss> ...
		cs := strings.Index(statStr, "(")
		ce := strings.LastIndex(statStr, ")")
		if cs < 0 || ce < 0 || ce+2 > len(statStr) {
			continue
		}
		comm   := statStr[cs+1 : ce]
		fields := strings.Fields(statStr[ce+2:])
		// 去除 comm 后字段偏移（0-indexed）：
		// [0]=state [11]=utime [12]=stime [20]=vsize(bytes) [21]=rss(pages)
		if len(fields) < 22 {
			continue
		}
		utime, _ := strconv.ParseUint(fields[11], 10, 64)
		stime, _ := strconv.ParseUint(fields[12], 10, 64)
		vsize, _ := strconv.ParseUint(fields[20], 10, 64)
		rss, _   := strconv.ParseInt(fields[21],  10, 64)

		totalJiffies := utime + stime
		newCPU[pid] = cpuSnapshot{jiffies: totalJiffies}

		virtKB := float64(vsize) / 1024.0
		resKB  := float64(rss) * pageKB

		// CPU%：与 top 的 Irix 模式（默认）保持一致，以单核为基准。
		// 公式：Δjiffies / USER_HZ / elapsed_seconds × 100
		// 不除以 numCPUs——与 top 默认行为一致，值域与原指标相同（可超过 100%）。
		// 防御 uint64 下溢（PID 复用时 jiffies 会重置）
		cpuPct := 0.0
		if !firstRun && elapsed > 0 {
			if prev, ok := prevCPU[pid]; ok && totalJiffies >= prev.jiffies {
				cpuPct = float64(totalJiffies-prev.jiffies) / clkTck / elapsed * 100.0
			}
		}

		// MEM%：进程 RSS / 系统总内存
		memPct := 0.0
		if memTotalKB > 0 {
			memPct = resKB / memTotalKB * 100.0
		}

		// ── /proc/<pid>/statm：共享内存页数（第 3 列）────────────────────
		shrKB := 0.0
		if statmData, err2 := os.ReadFile(procDir + "/statm"); err2 == nil {
			if f := strings.Fields(string(statmData)); len(f) >= 3 {
				if shrPages, err3 := strconv.ParseInt(f[2], 10, 64); err3 == nil {
					shrKB = float64(shrPages) * pageKB
				}
			}
		}

		// ── /proc/<pid>/status：获取进程属主 UID ─────────────────────────
		username := pidStr // 兜底：无法解析时用 PID 字符串
		if statusData, err2 := os.ReadFile(procDir + "/status"); err2 == nil {
			for _, line := range strings.Split(string(statusData), "\n") {
				if strings.HasPrefix(line, "Uid:") {
					if f := strings.Fields(line); len(f) >= 2 {
						if uid64, err3 := strconv.ParseUint(f[1], 10, 32); err3 == nil {
							username = lookupUsername(uint32(uid64))
						}
					}
					break
				}
			}
		}

		// ── /proc/<pid>/cmdline：完整命令行（\0 分隔，截断到 100 字符后首个空格）──
		cmdline := comm
		if cmdData, err2 := os.ReadFile(procDir + "/cmdline"); err2 == nil && len(cmdData) > 0 {
			raw := strings.TrimSpace(strings.ReplaceAll(string(cmdData), "\x00", " "))
			cmdline = truncateAtSpace(raw, 100)
		}

		result.perProc = append(result.perProc, perProcMetrics{
			pid:     pid,
			comm:    comm,
			user:    username,
			cmdline: cmdline,
			cpuPct:  cpuPct,
			memPct:  memPct,
			virtKB:  virtKB,
			resKB:   resKB,
			shrKB:   shrKB,
		})

		// ── /proc/<pid>/fd：FD 计数，用最小堆维护 Top-100 ─────────────────
		fdCount := countFDsByDir(procDir + "/fd")
		if fdCount > 0 {
			fdMax := getMaxFD(pid)
			item  := ProcessFDInfo{PID: pidStr, Name: comm, FDCount: fdCount, MaxFD: fdMax}
			if h.Len() < topK {
				heap.Push(h, item)
			} else if (*h)[0].FDCount < fdCount {
				// 当前堆顶比 item 小，弹出堆顶、压入新 item 以维护 Top-K
				heap.Pop(h)
				heap.Push(h, item)
			}
		}

		// ── /proc/<pid>/io：磁盘 IO 速率（跨周期差分，替代 pidstat -d -l 1 1）──
		// 【核心优化】pidstat 需等待至少 1 秒；直接读 /proc/<pid>/io 无等待开销
		if ioData, err2 := os.ReadFile(procDir + "/io"); err2 == nil {
			var rb, wb uint64
			for _, line := range strings.Split(string(ioData), "\n") {
				if strings.HasPrefix(line, "read_bytes:") {
					rb, _ = strconv.ParseUint(strings.TrimSpace(line[11:]), 10, 64)
				} else if strings.HasPrefix(line, "write_bytes:") {
					wb, _ = strconv.ParseUint(strings.TrimSpace(line[12:]), 10, 64)
				}
			}
			newIO[pid] = ioSnapshot{readBytes: rb, writeBytes: wb}
			if !firstRun && elapsed > 0 {
				if prev, ok := prevIO[pid]; ok {
					// 防御 uint64 下溢（PID 复用后计数重置）
					if rb >= prev.readBytes {
						if rKBs := float64(rb-prev.readBytes) / 1024.0 / elapsed; rKBs > 0 {
							result.diskReadKBs[pidStr] = rKBs
							result.diskComm[pidStr]    = comm
						}
					}
					if wb >= prev.writeBytes {
						if wKBs := float64(wb-prev.writeBytes) / 1024.0 / elapsed; wKBs > 0 {
							result.diskWriteKBs[pidStr] = wKBs
							result.diskComm[pidStr]     = comm
						}
					}
				}
			}
		}
	}

	// 从最小堆逆序提取，得到按 FDCount 降序排列的切片
	n := h.Len()
	result.topFDs = make([]ProcessFDInfo, n)
	for i := n - 1; i >= 0; i-- {
		result.topFDs[i] = heap.Pop(h).(ProcessFDInfo)
	}

	// 持锁写回跨周期状态
	c.statsMu.Lock()
	c.prevIOStats = newIO
	c.prevCPUStat = newCPU
	c.prevTime    = now
	c.statsMu.Unlock()

	return result, nil
}

// runSS 执行 ss -tulnp 并返回输出行。
// 接受父 ctx，在其基础上派生 5s 子超时（实际生效值 = min(父剩余, 5s)）。
func runSS(parentCtx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ss", "-tulnp").Output()
	if err != nil {
		return nil, err
	}
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines, nil
}

// getDbPids 通过 docker ps + docker inspect 获取 k8s DB 容器的宿主机 PID 及实例名。
// 【修复】① 去掉多余的 -a 标志（与 status=running 同用时 -a 无实际效果）
// 【修复】② 用 strings.Fields 代替 strings.Split(" ")，更健壮地处理多余空格
// 【修复】③ 增加 len(lists) < 3 越界保护，避免空行 index out of range
// getDbPids 接受父 ctx，在其基础上派生 10s 子超时（实际生效值 = min(父剩余, 10s)）。
// docker ps 和 docker inspect 共享这个子 ctx，两条命令合计不超过 10s。
func (c *processCollector) getDbPids(parentCtx context.Context) (map[string]string, map[string]string, error) {
	pidmysqls := make(map[string]string)
	pidtypes  := make(map[string]string)

	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "ps", "-q",
		"--filter", "status=running",
		"--filter", "name=k8s_mysql_",
		"--filter", "name=k8s_redis_",
		"--filter", "name=k8s_mongo_",
	).Output()
	if err != nil {
		return pidmysqls, pidtypes, nil // docker 不可用，静默返回空 map
	}

	ids := strings.Fields(strings.TrimSpace(string(out)))
	if len(ids) == 0 {
		return pidmysqls, pidtypes, nil
	}

	args := append([]string{
		"inspect", "-f",
		`{{.State.Pid}} {{index .Config.Labels "io.kubernetes.pod.name"}} {{index .Config.Labels "io.kubernetes.container.name"}}`,
	}, ids...)

	// 复用同一个 ctx：两条 docker 命令共享 10s 总预算，而非各自独立计时
	inspectOut, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		return pidmysqls, pidtypes, nil
	}

	for _, line := range strings.Split(strings.TrimSpace(string(inspectOut)), "\n") {
		lists := strings.Fields(line)
		if len(lists) < 3 {
			continue
		}
		pid    := lists[0]
		dbname := lists[1]
		dbtype := lists[2]

		if idx := strings.Index(dbname, "-deploy"); idx != -1 {
			dbname = dbname[:idx]
		}

		// 在进程树中查找真正的 DB 进程（如 mysqld 在容器 init 进程之下）
		if targetComm, ok := dbTypeToComm[dbtype]; ok {
			if newPid, err := findChildProcess(pid, targetComm); err == nil {
				pid = newPid
			}
		}
		pidmysqls[pid] = dbname
		pidtypes[pid]  = dbtype
	}
	return pidmysqls, pidtypes, nil
}

// =============================================================================
// 以下函数来自原始代码，逻辑保持不变（仅作格式整理）
// =============================================================================

func (c *processCollector) getAllocatedThreads() (int, map[string]int32, int, map[string]int32, error) {
	p, err := c.fs.AllProcs()
	if err != nil {
		return 0, nil, 0, nil, fmt.Errorf("unable to list all processes: %w", err)
	}
	pids := 0
	thread := 0
	procStates   := make(map[string]int32)
	threadStates := make(map[string]int32)

	for _, pid := range p {
		stat, err := pid.Stat()
		if err != nil {
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

// findChildProcess 从 parentPid 出发，在进程树中查找 comm 为 targetComm 的子进程
func findChildProcess(parentPid string, targetComm string) (string, error) {
	ppid, err := strconv.Atoi(parentPid)
	if err != nil {
		return parentPid, err
	}
	return findRecursive(ppid, targetComm, 0)
}

// findRecursive 递归查找目标进程，最大深度 3 层。
// 【修复】原 depth > 3 实际允许递归 5 层（depth=0,1,2,3,4），改为 depth >= 3 精确限制 3 层。
func findRecursive(pid int, target string, depth int) (string, error) {
	if depth >= 3 {
		return "", fmt.Errorf("max depth exceeded")
	}
	children, err := getChildrenPIDs(pid)
	if err != nil {
		return "", err
	}
	for _, child := range children {
		if comm, _ := getProcessComm(child); comm == target {
			return strconv.Itoa(child), nil
		}
		if found, err := findRecursive(child, target, depth+1); err == nil {
			return found, nil
		}
	}
	return "", fmt.Errorf("target process not found")
}

// getChildrenPIDs 从 /proc/<pid>/task/<pid>/children 读取直接子进程 PID 列表
func getChildrenPIDs(pid int) ([]int, error) {
	pidStr := strconv.Itoa(pid)
	data, err := os.ReadFile(filepath.Join("/proc", pidStr, "task", pidStr, "children"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, s := range strings.Fields(string(data)) {
		if p, err := strconv.Atoi(s); err == nil && p > 0 {
			pids = append(pids, p)
		}
	}
	return pids, nil
}

// getProcessComm 从 /proc/<pid>/comm 读取进程短名
func getProcessComm(pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
