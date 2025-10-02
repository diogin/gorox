// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// General QUIX (QUIC over UDP/UDS) Network Proxy implementation.

package hemi

import (
	"regexp"
)

// quixCase
type quixCase struct {
	// Parent
	case_
	// Assocs
	router  *QUIXRouter
	dealets []QUIXDealet
	// States
	matcher func(kase *quixCase, conn *QUIXConn, value []byte) bool
}

func (c *quixCase) onCreate(compName string, router *QUIXRouter) {
	c.MakeComp(compName)
	c.router = router
}
func (c *quixCase) OnShutdown() { c.router.DecCase() }

func (c *quixCase) OnConfigure() {
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
	if matcher, ok := quixCaseMatchers[cond.compare]; ok {
		c.matcher = matcher
	} else {
		UseExitln("unknown compare in case condition")
	}
}
func (c *quixCase) OnPrepare() {
}

func (c *quixCase) addDealet(dealet QUIXDealet) { c.dealets = append(c.dealets, dealet) }

func (c *quixCase) isMatch(conn *QUIXConn) bool {
	if c.general {
		return true
	}
	value := conn.riskyVariable(c.varCode, c.varName)
	return c.matcher(c, conn, value)
}

func (c *quixCase) execute(conn *QUIXConn) (dealt bool) {
	// TODO
	return false
}

var quixCaseMatchers = map[string]func(kase *quixCase, conn *QUIXConn, value []byte) bool{
	"==": (*quixCase).equalMatch,
	"^=": (*quixCase).prefixMatch,
	"$=": (*quixCase).suffixMatch,
	"*=": (*quixCase).containMatch,
	"~=": (*quixCase).regexpMatch,
	"!=": (*quixCase).notEqualMatch,
	"!^": (*quixCase).notPrefixMatch,
	"!$": (*quixCase).notSuffixMatch,
	"!*": (*quixCase).notContainMatch,
	"!~": (*quixCase).notRegexpMatch,
}

func (c *quixCase) equalMatch(conn *QUIXConn, value []byte) bool { // value == patterns
	return equalMatch(value, c.patterns)
}
func (c *quixCase) prefixMatch(conn *QUIXConn, value []byte) bool { // value ^= patterns
	return prefixMatch(value, c.patterns)
}
func (c *quixCase) suffixMatch(conn *QUIXConn, value []byte) bool { // value $= patterns
	return suffixMatch(value, c.patterns)
}
func (c *quixCase) containMatch(conn *QUIXConn, value []byte) bool { // value *= patterns
	return containMatch(value, c.patterns)
}
func (c *quixCase) regexpMatch(conn *QUIXConn, value []byte) bool { // value ~= patterns
	return regexpMatch(value, c.regexps)
}
func (c *quixCase) notEqualMatch(conn *QUIXConn, value []byte) bool { // value != patterns
	return notEqualMatch(value, c.patterns)
}
func (c *quixCase) notPrefixMatch(conn *QUIXConn, value []byte) bool { // value !^ patterns
	return notPrefixMatch(value, c.patterns)
}
func (c *quixCase) notSuffixMatch(conn *QUIXConn, value []byte) bool { // value !$ patterns
	return notSuffixMatch(value, c.patterns)
}
func (c *quixCase) notContainMatch(conn *QUIXConn, value []byte) bool { // value !* patterns
	return notContainMatch(value, c.patterns)
}
func (c *quixCase) notRegexpMatch(conn *QUIXConn, value []byte) bool { // value !~ patterns
	return notRegexpMatch(value, c.regexps)
}

// QUIXDealet
type QUIXDealet interface {
	// Imports
	Component
	// Methods
	DealWith(conn *QUIXConn, stream *QUIXStream) (dealt bool)
}

// QUIXDealet_ is a parent.
type QUIXDealet_ struct { // for all quix dealets
	// Parent
	dealet_
	// States
}

func (d *QUIXDealet_) OnCreate(compName string, stage *Stage) {
	d.MakeComp(compName)
	d.stage = stage
}

func init() {
	RegisterQUIXDealet("quixProxy", func(compName string, stage *Stage, router *QUIXRouter) QUIXDealet {
		d := new(quixProxy)
		d.onCreate(compName, stage, router)
		return d
	})
}

// quixProxy dealet passes QUIX connections to QUIX backends.
type quixProxy struct {
	// Parent
	QUIXDealet_
	// Assocs
	router  *QUIXRouter  // the router to which the dealet belongs
	backend *QUIXBackend // the backend to pass to
	// States
	QUIXProxyConfig // embeded
}

func (d *quixProxy) onCreate(compName string, stage *Stage, router *QUIXRouter) {
	d.QUIXDealet_.OnCreate(compName, stage)
	d.router = router
}
func (d *quixProxy) OnShutdown() { d.router.DecDealet() }

func (d *quixProxy) OnConfigure() {
	// .toBackend
	if v, ok := d.Find("toBackend"); ok {
		if compName, ok := v.String(); ok && compName != "" {
			if backend := d.stage.Backend(compName); backend == nil {
				UseExitf("unknown backend: '%s'\n", compName)
			} else if quixBackend, ok := backend.(*QUIXBackend); ok {
				d.backend = quixBackend
			} else {
				UseExitf("incorrect backend '%s' for quixProxy\n", compName)
			}
		} else {
			UseExitln("invalid toBackend")
		}
	} else {
		UseExitln("toBackend is required for quixProxy")
	}
}
func (d *quixProxy) OnPrepare() {
}

func (d *quixProxy) DealWith(conn *QUIXConn, stream *QUIXStream) (dealt bool) {
	QUIXReverseProxy(conn, stream, d.backend, &d.QUIXProxyConfig)
	return true
}

// QUIXProxyConfig
type QUIXProxyConfig struct {
	// TODO
}

// QUIXReverseProxy
func QUIXReverseProxy(servConn *QUIXConn, servStream *QUIXStream, backend *QUIXBackend, proxyConfig *QUIXProxyConfig) {
	// TODO
}
