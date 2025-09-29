// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// Auxiliary types and functions of the operating system.

package system

import (
	"os"
	"path/filepath"
	"runtime"
)

var (
	ExePath string
	ExeDir  string
)

func init() {
	// set public variables
	exePath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	ExePath = exePath
	ExeDir = filepath.Dir(exePath)
	if runtime.GOOS == "windows" { // change '\\' to '/'
		ExePath = filepath.ToSlash(ExePath)
		ExeDir = filepath.ToSlash(ExeDir)
	}
}
