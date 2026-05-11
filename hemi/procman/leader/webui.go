// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// WebUI server.

package leader

import (
	"fmt"

	"github.com/diogin/gorox/hemi/library/msgx"
	"github.com/diogin/gorox/hemi/procman/common"

	. "github.com/diogin/gorox/hemi"
)

var webChan = make(chan *msgx.Message) // used to send messages to workerManager

func webuiServer() { // runner
	if DebugLevel() >= 1 {
		Printf("[leader] open webui interface: %s\n", common.WebUIAddr)
	}
	RegisterHandlet("webHandlet", func(compName string, stage *Stage, webapp *Webapp) Handlet {
		h := new(webHandlet)
		h.onCreate(compName, stage, webapp)
		return h
	})
	// TODO
	webStage, err := StageFromText(fmt.Sprintf(webConfig, common.WebUIAddr))
	if err != nil {
		common.Crash(err.Error())
	}
	webStage.Start(0)
	select {}
}

var webConfig = `
stage {
    webapp "webui" {
        .hostnames = ("*")
        .webRoot = %%topDir + "/misc/webui"
        rule $path == "/favicon.ico" {
            favicon {}
        }
        rule $path -f {
            static {
                .autoIndex = true
            }
        }
        rule {
            webHandlet {}
        }
    }
    httpxServer "webui" {
        .webapps = ("webui")
        .address = "%s"
	.numGates = 1
    }
}
`

type webHandlet struct {
	Handlet_
}

func (h *webHandlet) onCreate(compName string, stage *Stage, webapp *Webapp) {
	h.Handlet_.OnCreate(compName, stage, webapp)
}
func (h *webHandlet) OnShutdown() { h.Webapp().DecHandlet() }

func (h *webHandlet) OnConfigure() {}
func (h *webHandlet) OnPrepare()   {}

func (h *webHandlet) Handle(req ServerRequest, resp ServerResponse) (next bool) {
	resp.Send("webui")
	return false
}
