// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// UDPX (UDP/UDS) types. See RFC 768 and RFC 8085.

package hemi

import (
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// udpxHolder
type udpxHolder interface {
	// Imports
	holder
	// Methods
}

// _udpxHolder_ is a mixin.
type _udpxHolder_ struct { // for udpxNode, UDPXRouter, and udpxGate
	// States
	// UDP_CORK, UDP_GSO, ...
}

func (h *_udpxHolder_) onConfigure(comp Component) {
}
func (h *_udpxHolder_) onPrepare(comp Component) {
}

// udpxConn collects shared methods between *UDPXConn and *UConn.
type udpxConn interface {
	ID() int64
	Holder() udpxHolder
	UDSMode() bool
}

// udpxConn_ is a parent.
type udpxConn_[H udpxHolder] struct { // for UDPXConn and UConn
	// Conn states (stocks)
	stockBuffer [256]byte // a (fake) buffer to workaround Go's conservative escape analysis
	// Conn states (controlled)
	// Conn states (non-zeros)
	id      int64 // the conn id
	holder  H     // udpxNode or udpxGate
	pktConn net.PacketConn
	rawConn syscall.RawConn // for syscall
	// Conn states (zeros)
	counter   atomic.Int64 // can be used to generate a random number
	lastRead  time.Time    // deadline of last read operation
	lastWrite time.Time    // deadline of last write operation
	broken    atomic.Bool
}

func (c *udpxConn_[H]) onGet(id int64, holder H, pktConn net.PacketConn, rawConn syscall.RawConn) {
	c.id = id
	c.holder = holder
	c.pktConn = pktConn
	c.rawConn = rawConn
}
func (c *udpxConn_[H]) onPut() {
	var null H // nil
	c.holder = null
	c.pktConn = nil
	c.rawConn = nil
	c.counter.Store(0)
	c.lastRead = time.Time{}
	c.lastWrite = time.Time{}
	c.broken.Store(false)
}

func (c *udpxConn_[H]) UDSMode() bool { return c.holder.UDSMode() }

func (c *udpxConn_[H]) MakeTempName(dst []byte, unixTime int64) int {
	return makeTempName(dst, c.holder.Stage().ID(), unixTime, c.id, c.counter.Add(1))
}

func (c *udpxConn_[H]) markBroken()    { c.broken.Store(true) }
func (c *udpxConn_[H]) isBroken() bool { return c.broken.Load() }

func (c *udpxConn_[H]) WriteTo(src []byte, addr net.Addr) (n int, err error) {
	return c.pktConn.WriteTo(src, addr)
}
func (c *udpxConn_[H]) ReadFrom(dst []byte) (n int, addr net.Addr, err error) {
	return c.pktConn.ReadFrom(dst)
}
