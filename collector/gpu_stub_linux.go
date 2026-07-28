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

//go:build linux && !nvml && !noprocesses
// +build linux,!nvml,!noprocesses

package collector

// GPU is kept to satisfy references from the processes collector when NVML is disabled.
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

func initNVML() {}

func getGPUInfo() ([]GPU, error) {
	return nil, nil
}

