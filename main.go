// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// Gorox server (leader & worker) and its control client.

package main

import (
	"github.com/diogin/gorox/hemi/process"

	_ "github.com/diogin/gorox/apps" // all web applications
	_ "github.com/diogin/gorox/exts" // all hemi extensions
	_ "github.com/diogin/gorox/svcs" // all rpc services
)

func main() {
	process.Main(&process.Opts{
		ProgramName:  "gorox",
		ProgramTitle: "Gorox",
		DebugLevel:   0,
		CmdUIAddr:    "127.0.0.1:9527",
		WebUIAddr:    "127.0.0.1:9528",
	})
}
