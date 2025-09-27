// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// WebUI server.

package leader

import (
	"github.com/diogin/gorox/hemi"
	"github.com/diogin/gorox/hemi/library/msgx"
	"github.com/diogin/gorox/hemi/process/common"

	_ "github.com/diogin/gorox/hemi/process/leader/webui"
)

var webChan = make(chan *msgx.Message) // used to send messages to workerKeeper

func webuiServer() { // runner
	if hemi.DebugLevel() >= 1 {
		hemi.Printf("[leader] open webui interface: %s\n", common.WebUIAddr)
	}
	// TODO
	//webStage := hemi.StageFromText()
}
