/*
Copyright 2019 The KubeSphere Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package version

import (
	"encoding/json"
	"fmt"
	"runtime"

	apimachineryversion "k8s.io/apimachinery/pkg/version"
)

var (
	gitVersion   = "v3.2.1"
	gitCommit    = "unknown"
	gitTreeState = "unknown"
	buildDate    = "unknown"
	gitMajor     = "unknown"
	gitMinor     = "unknown"
)

type Info struct {
	GitVersion   string                    `json:"gitVersion"`
	GitMajor     string                    `json:"gitMajor"`
	GitMinor     string                    `json:"gitMinor"`
	GitCommit    string                    `json:"gitCommit"`
	GitTreeState string                    `json:"gitTreeState"`
	BuildDate    string                    `json:"buildDate"`
	GoVersion    string                    `json:"goVersion"`
	Compiler     string                    `json:"compiler"`
	Platform     string                    `json:"platform"`
	Kubernetes   *apimachineryversion.Info `json:"kubernetes,omitempty"`
}

func (info Info) String() string {
	jsonString, _ := json.Marshal(info)
	return string(jsonString)
}

// Get returns the overall codebase version. It's for
// detecting what code a binary was built from.
func Get() Info {
	// These variables typically come from -ldflags settings and
	// in their absence fallback to the default settings
	return Info{
		GitVersion:   gitVersion,
		GitMajor:     gitMajor,
		GitMinor:     gitMinor,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
