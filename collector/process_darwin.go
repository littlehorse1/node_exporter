//go:build !noprocess
// +build !noprocess

package collector

import (
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	processInfoSubsystem = "process"
)

type processCollector struct {
	logger log.Logger
}

func init() {
	registerCollector("process", defaultEnabled, NewProcessCollector)
}

// NewProcessCollector returns a new Collector exposing memory stats.
func NewProcessCollector(logger log.Logger) (Collector, error) {
	return &processCollector{logger}, nil
}

// Update calls (*processCollector).getMemInfo to get the platform specific
// process metrics.
func (c *processCollector) Update(ch chan<- prometheus.Metric) error {

	cmd := exec.Command("ps", "ax", "-o", "%cpu,%mem,rss,pid,ppid,command")

	// Run the command and capture the output
	output, err := cmd.Output()
	if err != nil {
		// Handle any errors that occurred while running the command
		level.Info(c.logger).Log("Process Error", err)
		return nil
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
		if err != nil {
			level.Info(c.logger).Log("Process Error", err)
			continue
		}
		Commandline := strings.Join(str[5:], " ")
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, processInfoSubsystem, "cpu"),
				"Mac Process Cpu",
				[]string{"pid"}, nil,
			),
			prometheus.GaugeValue, Cpu, Pid,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, processInfoSubsystem, "mem"),
				"Mac Process Mem",
				[]string{"pid"}, nil,
			),
			prometheus.GaugeValue, Mem, Pid,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, processInfoSubsystem, "rss"),
				"Mac Process Rss",
				[]string{"pid"}, nil,
			),
			prometheus.GaugeValue, Rss, Pid,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, processInfoSubsystem, "ppid"),
				"Mac Process Ppid",
				[]string{"ppid", "pid"}, nil,
			),
			prometheus.GaugeValue, 1, Ppid, Pid,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, processInfoSubsystem, "command"),
				"Mac Process Commandline",
				[]string{"command", "pid"}, nil,
			),
			prometheus.GaugeValue, 1.0, Commandline, str[3],
		)
	}
	cmd.Process.Kill()
	cmd = exec.Command("nettop", "-J", "bytes_in,bytes_out", "-P", "-x", "-d", "-l", "1")
	// Run the command and capture the output
	output, err = cmd.Output()
	if err != nil {
		// Handle any errors that occurred while running the command
		level.Info(c.logger).Log("Process Error", err)
		return nil
	}
	result = strings.Split(strings.TrimSpace(string(output)), "\n")
	re = regexp.MustCompile(`\s+`)
	for _, s := range result[1:] {
		formatStr := re.ReplaceAllString(strings.TrimSpace(s), " ")
		str := strings.Split(formatStr, " ")
		processname := strings.Split(str[1], ".")
		Pid := processname[len(processname)-1]
		bytes_in, err := strconv.ParseFloat(str[2], 64)
		if err != nil {
			continue
		}
		bytes_out, err := strconv.ParseFloat(str[3], 64)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, processInfoSubsystem, "network_in"),
				"Mac Process network in",
				[]string{"pid"}, nil,
			),
			prometheus.GaugeValue, bytes_in, Pid,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, processInfoSubsystem, "network_out"),
				"Mac Process network out",
				[]string{"pid"}, nil,
			),
			prometheus.GaugeValue, bytes_out, Pid,
		)
	}
	cmd = exec.Command("pkill", "nettop")
	output, err = cmd.Output()
	if err != nil {
		// Handle any errors that occurred while running the command
		level.Info(c.logger).Log("nettop Error", err)
	}

	return nil
}
