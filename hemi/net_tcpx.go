// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// General TCPX (TCP/TLS/UDS) Network Proxy implementation.

package hemi

import (
	"regexp"
)

// tcpxCase
type tcpxCase struct {
	// Parent
	case_
	// Assocs
	router  *TCPXRouter
	dealets []TCPXDealet
	// States
	matcher func(kase *tcpxCase, conn *TCPXConn, value []byte) bool
}

func (c *tcpxCase) onCreate(compName string, router *TCPXRouter) {
	c.MakeComp(compName)
	c.router = router
}
func (c *tcpxCase) OnShutdown() { c.router.DecCase() }

func (c *tcpxCase) OnConfigure() {
	if c.info == nil {
		c.general = true
		return
	}
	cond := c.info.(caseCond)
	c.varCode = cond.varCode
	c.varName = cond.varName
	isRegexp := cond.compare == "~=" || cond.compare == "!~"
	for _, pattern := range cond.patterns {
		if pattern == "" {
			UseExitln("empty case cond pattern")
		}
		if !isRegexp {
			c.patterns = append(c.patterns, []byte(pattern))
		} else if exp, err := regexp.Compile(pattern); err == nil {
			c.regexps = append(c.regexps, exp)
		} else {
			UseExitln(err.Error())
		}
	}
	if matcher, ok := tcpxCaseMatchers[cond.compare]; ok {
		c.matcher = matcher
	} else {
		UseExitln("unknown compare in case condition")
	}
}
func (c *tcpxCase) OnPrepare() {
}

func (c *tcpxCase) addDealet(dealet TCPXDealet) { c.dealets = append(c.dealets, dealet) }

func (c *tcpxCase) isMatch(conn *TCPXConn) bool {
	if c.general {
		return true
	}
	value := conn.riskyVariable(c.varCode, c.varName)
	return c.matcher(c, conn, value)
}

func (c *tcpxCase) execute(conn *TCPXConn) (dealt bool) {
	for _, dealet := range c.dealets {
		if dealt := dealet.DealWith(conn); dealt {
			return true
		}
	}
	return false
}

var tcpxCaseMatchers = map[string]func(kase *tcpxCase, conn *TCPXConn, value []byte) bool{
	"==": (*tcpxCase).equalMatch,
	"^=": (*tcpxCase).prefixMatch,
	"$=": (*tcpxCase).suffixMatch,
	"*=": (*tcpxCase).containMatch,
	"~=": (*tcpxCase).regexpMatch,
	"!=": (*tcpxCase).notEqualMatch,
	"!^": (*tcpxCase).notPrefixMatch,
	"!$": (*tcpxCase).notSuffixMatch,
	"!*": (*tcpxCase).notContainMatch,
	"!~": (*tcpxCase).notRegexpMatch,
}

func (c *tcpxCase) equalMatch(conn *TCPXConn, value []byte) bool { // value == patterns
	return equalMatch(value, c.patterns)
}
func (c *tcpxCase) prefixMatch(conn *TCPXConn, value []byte) bool { // value ^= patterns
	return prefixMatch(value, c.patterns)
}
func (c *tcpxCase) suffixMatch(conn *TCPXConn, value []byte) bool { // value $= patterns
	return suffixMatch(value, c.patterns)
}
func (c *tcpxCase) containMatch(conn *TCPXConn, value []byte) bool { // value *= patterns
	return containMatch(value, c.patterns)
}
func (c *tcpxCase) regexpMatch(conn *TCPXConn, value []byte) bool { // value ~= patterns
	return regexpMatch(value, c.regexps)
}
func (c *tcpxCase) notEqualMatch(conn *TCPXConn, value []byte) bool { // value != patterns
	return notEqualMatch(value, c.patterns)
}
func (c *tcpxCase) notPrefixMatch(conn *TCPXConn, value []byte) bool { // value !^ patterns
	return notPrefixMatch(value, c.patterns)
}
func (c *tcpxCase) notSuffixMatch(conn *TCPXConn, value []byte) bool { // value !$ patterns
	return notSuffixMatch(value, c.patterns)
}
func (c *tcpxCase) notContainMatch(conn *TCPXConn, value []byte) bool { // value !* patterns
	return notContainMatch(value, c.patterns)
}
func (c *tcpxCase) notRegexpMatch(conn *TCPXConn, value []byte) bool { // value !~ patterns
	return notRegexpMatch(value, c.regexps)
}

// TCPXDealet
type TCPXDealet interface {
	// Imports
	Component
	// Methods
	DealWith(conn *TCPXConn) (dealt bool)
}

// TCPXDealet_ is a parent.
type TCPXDealet_ struct { // for all tcpx dealets
	// Parent
	dealet_
	// States
}

func (d *TCPXDealet_) OnCreate(compName string, stage *Stage) {
	d.MakeComp(compName)
	d.stage = stage
}

func init() {
	RegisterTCPXDealet("tcpxProxy", func(compName string, stage *Stage, router *TCPXRouter) TCPXDealet {
		d := new(tcpxProxy)
		d.onCreate(compName, stage, router)
		return d
	})
}

// tcpxProxy dealet passes TCPX connections to TCPX backends.
type tcpxProxy struct {
	// Parent
	TCPXDealet_
	// Assocs
	router  *TCPXRouter  // the router to which the dealet belongs
	backend *TCPXBackend // the backend to pass to
	// States
	TCPXProxyConfig // embeded
}

func (d *tcpxProxy) onCreate(compName string, stage *Stage, router *TCPXRouter) {
	d.TCPXDealet_.OnCreate(compName, stage)
	d.router = router
}
func (d *tcpxProxy) OnShutdown() { d.router.DecDealet() }

func (d *tcpxProxy) OnConfigure() {
	// .toBackend
	if v, ok := d.Find("toBackend"); ok {
		if compName, ok := v.String(); ok && compName != "" {
			if backend := d.stage.Backend(compName); backend == nil {
				UseExitf("unknown backend: '%s'\n", compName)
			} else if tcpxBackend, ok := backend.(*TCPXBackend); ok {
				d.backend = tcpxBackend
			} else {
				UseExitf("incorrect backend '%s' for tcpxProxy\n", compName)
			}
		} else {
			UseExitln("invalid toBackend")
		}
	} else {
		UseExitln("toBackend is required for tcpxProxy proxy")
	}
}
func (d *tcpxProxy) OnPrepare() {
	// Currently nothing.
}

func (d *tcpxProxy) DealWith(conn *TCPXConn) (dealt bool) {
	TCPXReverseProxy(conn, d.backend, &d.TCPXProxyConfig)
	return true
}

// TCPXProxyConfig
type TCPXProxyConfig struct {
	// Inbound
	// Outbound
}

// TCPXReverseProxy
func TCPXReverseProxy(servConn *TCPXConn, backend *TCPXBackend, proxyConfig *TCPXProxyConfig) {
	backConn, err := backend.Dial()
	if err != nil {
		servConn.Close()
		return
	}
	inboundOver := make(chan struct{}, 1)
	// Pass inbound data
	go func() {
		var (
			servErr error
			backErr error
			inData  []byte
		)
		for {
			if servErr = servConn.SetReadDeadline(); servErr == nil { // for server-side incoming increment
				if inData, servErr = servConn.Recv(); len(inData) > 0 {
					if backErr = backConn.SetWriteDeadline(); backErr == nil { // for backend-side outgoing increment
						backErr = backConn.Send(inData)
					}
				}
			}
			if servErr != nil || backErr != nil {
				servConn.CloseRead()
				backConn.CloseWrite()
				break
			}
		}
		inboundOver <- struct{}{}
	}()
	// Pass outbound data
	var (
		backErr error
		servErr error
		outData []byte
	)
	for {
		if backErr = backConn.SetReadDeadline(); backErr == nil { // for backend-side incoming increment
			if outData, backErr = backConn.Recv(); len(outData) > 0 {
				if servErr = servConn.SetWriteDeadline(); servErr == nil { // for server-side outgoing increment
					servErr = servConn.Send(outData)
				}
			}
		}
		if backErr != nil || servErr != nil {
			backConn.CloseRead()
			servConn.CloseWrite()
			break
		}
	}
	<-inboundOver
}
