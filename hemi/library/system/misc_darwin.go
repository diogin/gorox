// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// Misc types and functions for macOS.

package system

import (
	"fmt"
)

func Check() bool {
	// ensure reuseport support?
	return true
}

func Advise() {
	fmt.Println("not implemented")
}
