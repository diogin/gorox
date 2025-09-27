// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// HemiCar server (leader & worker) and its control client.

package main

import (
	"github.com/diogin/gorox/hemi/process"

	_ "github.com/diogin/gorox/hemi/hemicar/apps"
	_ "github.com/diogin/gorox/hemi/hemicar/exts"
	_ "github.com/diogin/gorox/hemi/hemicar/svcs"
)

func main() {
	process.Main(&process.Opts{
		ProgramName:  "hemicar",
		ProgramTitle: "HemiCar",
		DebugLevel:   2,
		CmdUIAddr:    "127.0.0.1:9523",
		WebUIAddr:    "127.0.0.1:9524",
	})
}
