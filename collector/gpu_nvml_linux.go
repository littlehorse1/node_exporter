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

//go:build linux && cgo && nvml && !noprocesses
// +build linux,cgo,nvml,!noprocesses

package collector

import (
	"fmt"
	"sync"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

// GPU represents a single GPU snapshot.
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

// NVML singleton: initialize once per process.
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
			_ = nvml.Shutdown()
			return
		}
		nvmlAvailable = true
		// Keep NVML initialized for the exporter lifetime.
	})
}

// getGPUInfo returns GPU metrics using NVML.
func getGPUInfo() ([]GPU, error) {
	initNVML()
	if !nvmlAvailable {
		return nil, nil
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

