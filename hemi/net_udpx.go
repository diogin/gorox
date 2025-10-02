// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// General UDPX (UDP/UDS) Network Proxy implementation.

package hemi

import (
	"regexp"
)

// udpxCase
type udpxCase struct {
	// Parent
	case_
	// Assocs
	router  *UDPXRouter
	dealets []UDPXDealet
	// States
	matcher func(kase *udpxCase, conn *UDPXConn, value []byte) bool
}

func (c *udpxCase) onCreate(compName string, router *UDPXRouter) {
	c.MakeComp(compName)
	c.router = router
}
func (c *udpxCase) OnShutdown() { c.router.DecCase() }

func (c *udpxCase) OnConfigure() {
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
	if matcher, ok := udpxCaseMatchers[cond.compare]; ok {
		c.matcher = matcher
	} else {
		UseExitln("unknown compare in case condition")
	}
}
func (c *udpxCase) OnPrepare() {
}

func (c *udpxCase) addDealet(dealet UDPXDealet) { c.dealets = append(c.dealets, dealet) }

func (c *udpxCase) isMatch(conn *UDPXConn) bool {
	if c.general {
		return true
	}
	value := conn.riskyVariable(c.varCode, c.varName)
	return c.matcher(c, conn, value)
}

func (c *udpxCase) execute(conn *UDPXConn) (dealt bool) {
	for _, dealet := range c.dealets {
		if dealt := dealet.DealWith(conn); dealt {
			return true
		}
	}
	return false
}

var udpxCaseMatchers = map[string]func(kase *udpxCase, conn *UDPXConn, value []byte) bool{
	"==": (*udpxCase).equalMatch,
	"^=": (*udpxCase).prefixMatch,
	"$=": (*udpxCase).suffixMatch,
	"*=": (*udpxCase).containMatch,
	"~=": (*udpxCase).regexpMatch,
	"!=": (*udpxCase).notEqualMatch,
	"!^": (*udpxCase).notPrefixMatch,
	"!$": (*udpxCase).notSuffixMatch,
	"!*": (*udpxCase).notContainMatch,
	"!~": (*udpxCase).notRegexpMatch,
}

func (c *udpxCase) equalMatch(conn *UDPXConn, value []byte) bool { // value == patterns
	return equalMatch(value, c.patterns)
}
func (c *udpxCase) prefixMatch(conn *UDPXConn, value []byte) bool { // value ^= patterns
	return prefixMatch(value, c.patterns)
}
func (c *udpxCase) suffixMatch(conn *UDPXConn, value []byte) bool { // value $= patterns
	return suffixMatch(value, c.patterns)
}
func (c *udpxCase) containMatch(conn *UDPXConn, value []byte) bool { // value *= patterns
	return containMatch(value, c.patterns)
}
func (c *udpxCase) regexpMatch(conn *UDPXConn, value []byte) bool { // value ~= patterns
	return regexpMatch(value, c.regexps)
}
func (c *udpxCase) notEqualMatch(conn *UDPXConn, value []byte) bool { // value != patterns
	return notEqualMatch(value, c.patterns)
}
func (c *udpxCase) notPrefixMatch(conn *UDPXConn, value []byte) bool { // value !^ patterns
	return notPrefixMatch(value, c.patterns)
}
func (c *udpxCase) notSuffixMatch(conn *UDPXConn, value []byte) bool { // value !$ patterns
	return notSuffixMatch(value, c.patterns)
}
func (c *udpxCase) notContainMatch(conn *UDPXConn, value []byte) bool { // value !* patterns
	return notContainMatch(value, c.patterns)
}
func (c *udpxCase) notRegexpMatch(conn *UDPXConn, value []byte) bool { // value !~ patterns
	return notRegexpMatch(value, c.regexps)
}

// UDPXDealet
type UDPXDealet interface {
	// Imports
	Component
	// Methods
	DealWith(conn *UDPXConn) (dealt bool)
}

// UDPXDealet_ is a parent.
type UDPXDealet_ struct { // for all udpx dealets
	// Parent
	dealet_
	// States
}

func (d *UDPXDealet_) OnCreate(compName string, stage *Stage) {
	d.MakeComp(compName)
	d.stage = stage
}

func init() {
	RegisterUDPXDealet("udpxProxy", func(compName string, stage *Stage, router *UDPXRouter) UDPXDealet {
		d := new(udpxProxy)
		d.onCreate(compName, stage, router)
		return d
	})
}

// udpxProxy dealet passes UDPX connections to UDPX backends.
type udpxProxy struct {
	// Parent
	UDPXDealet_
	// Assocs
	router  *UDPXRouter  // the router to which the dealet belongs
	backend *UDPXBackend // the backend to pass to
	// States
	UDPXProxyConfig // embeded
}

func (d *udpxProxy) onCreate(compName string, stage *Stage, router *UDPXRouter) {
	d.UDPXDealet_.OnCreate(compName, stage)
	d.router = router
}
func (d *udpxProxy) OnShutdown() { d.router.DecDealet() }

func (d *udpxProxy) OnConfigure() {
	// .toBackend
	if v, ok := d.Find("toBackend"); ok {
		if compName, ok := v.String(); ok && compName != "" {
			if backend := d.stage.Backend(compName); backend == nil {
				UseExitf("unknown backend: '%s'\n", compName)
			} else if udpxBackend, ok := backend.(*UDPXBackend); ok {
				d.backend = udpxBackend
			} else {
				UseExitf("incorrect backend '%s' for udpxProxy\n", compName)
			}
		} else {
			UseExitln("invalid toBackend")
		}
	} else {
		UseExitln("toBackend is required for udpxProxy")
	}
}
func (d *udpxProxy) OnPrepare() {
}

func (d *udpxProxy) DealWith(conn *UDPXConn) (dealt bool) {
	UDPXReverseProxy(conn, d.backend, &d.UDPXProxyConfig)
	return true
}

// UDPXProxyConfig
type UDPXProxyConfig struct {
	// TODO
}

// UDPXReverseProxy
func UDPXReverseProxy(servConn *UDPXConn, backend *UDPXBackend, proxyConfig *UDPXProxyConfig) {
	// TODO
}
