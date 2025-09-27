// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// Process for FreeBSD.

package system

import (
	"syscall"
)

func DaemonSysAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
func DaemonInit() {
}

func SetAffinity(pid int, cpu int) bool {
	return true
}
