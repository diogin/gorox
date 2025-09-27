// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// GoroxIO server (leader & worker) and its control client.

package main

import (
	"github.com/diogin/gorox/hemi/process"

	_ "github.com/diogin/gorox/hemi/goroxio/apps"
	_ "github.com/diogin/gorox/hemi/goroxio/exts"
)

func main() {
	process.Main(&process.Opts{
		ProgramName:  "goroxio",
		ProgramTitle: "GoroxIO",
		DebugLevel:   1,
		CmdUIAddr:    "127.0.0.1:9525",
		WebUIAddr:    "127.0.0.1:9526",
	})
}
