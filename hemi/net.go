// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// General Network Proxy implementation.

package hemi

import (
	"regexp"
)

// router_ is a parent.
type router_[G Gate] struct { // for QUIXRouter, TCPXRouter, and UDPXRouter
	// Parent
	Server_[G]
	// Mixins
	_accessLogger_ // routers can log accesses
}

func (r *router_[G]) onCreate(compName string, stage *Stage) {
	r.Server_.OnCreate(compName, stage)
}

func (r *router_[G]) onConfigure() {
	r.Server_.OnConfigure()
	r._accessLogger_.onConfigure(r)
}
func (r *router_[G]) onPrepare() {
	r.Server_.OnPrepare()
	r._accessLogger_.onPrepare(r)
}

func (r *router_[G]) DecDealet() { r.subs.Done() }
func (r *router_[G]) DecCase()   { r.subs.Done() }

// case_
type case_ struct { // for quixCase, tcpxCase, and udpxCase
	// Parent
	Component_
	// Assocs
	// States
	generic  bool             // generic match?
	varCode  int16            // the variable code
	varName  string           // the variable name
	patterns [][]byte         // condition patterns
	regexps  []*regexp.Regexp // pre-compiled patterns
}

// dealet_
type dealet_ struct { // for QUIXDealet_, TCPXDealet_, and UDPXDealet_
	// Parent
	Component_
	// Assocs
	stage *Stage
	// States
}

func (d *dealet_) Stage() *Stage { return d.stage }
