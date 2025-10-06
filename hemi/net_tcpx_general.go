// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// TCPX (TCP/TLS/UDS) types. See RFC 9293.

package hemi

import (
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// tcpxHolder
type tcpxHolder interface {
	// Imports
	holder
	// Methods
}

// _tcpxHolder_ is a mixin.
type _tcpxHolder_ struct { // for tcpxNode, TCPXRouter, and tcpxGate
	// States
	// TCP_CORK, TCP_DEFER_ACCEPT, TCP_FASTOPEN, ...
}

func (h *_tcpxHolder_) onConfigure(comp Component) {
}
func (h *_tcpxHolder_) onPrepare(comp Component) {
}

// tcpxConn collects shared methods between *TCPXConn and *TConn.
type tcpxConn interface {
	ID() int64
	Holder() tcpxHolder
	UDSMode() bool
	TLSMode() bool
	MakeTempName(dst []byte, unixTime int64) int
	markBroken()
	isBroken() bool
}

// tcpxConn_ is a parent.
type tcpxConn_[H tcpxHolder] struct { // for TCPXConn and TConn
	// Conn states (stocks)
	stockBuffer [256]byte  // a (fake) buffer to workaround Go's conservative escape analysis
	stockInput  [8192]byte // for c.input
	// Conn states (controlled)
	// Conn states (non-zeros)
	id        int64           // the conn id
	holder    H               // tcpxNode or tcpxGate
	netConn   net.Conn        // *net.TCPConn, *tls.Conn, *net.UnixConn
	rawConn   syscall.RawConn // for syscall, only usable when netConn is TCP/UDS
	input     []byte          // input buffer
	region    Region          // a region-based memory pool
	closeSema atomic.Int32    // controls read/write close
	// Conn states (zeros)
	counter     atomic.Int64 // can be used to generate a random number
	lastRead    time.Time    // deadline of last read operation
	lastWrite   time.Time    // deadline of last write operation
	broken      atomic.Bool  // is connection broken?
	Vector      net.Buffers  // used by SendVector()
	FixedVector [4][]byte    // used by SendVector()
}

func (c *tcpxConn_[H]) onGet(id int64, holder H, netConn net.Conn, rawConn syscall.RawConn) {
	c.id = id
	c.holder = holder
	c.netConn = netConn
	c.rawConn = rawConn
	c.input = c.stockInput[:]
	c.region.Init()
	c.closeSema.Store(2)
}
func (c *tcpxConn_[H]) onPut() {
	var null H // nil
	c.holder = null
	c.netConn = nil
	c.rawConn = nil
	if cap(c.input) != cap(c.stockInput) {
		PutNK(c.input)
	}
	c.input = nil
	c.region.Free()

	c.counter.Store(0)
	c.lastRead = time.Time{}
	c.lastWrite = time.Time{}
	c.broken.Store(false)
	c.Vector = nil
	c.FixedVector = [4][]byte{}
}

func (c *tcpxConn_[H]) UDSMode() bool { return c.holder.UDSMode() }
func (c *tcpxConn_[H]) TLSMode() bool { return c.holder.TLSMode() }

func (c *tcpxConn_[H]) MakeTempName(dst []byte, unixTime int64) int {
	return makeTempName(dst, c.holder.Stage().ID(), unixTime, c.id, c.counter.Add(1))
}

func (c *tcpxConn_[H]) markBroken()    { c.broken.Store(true) }
func (c *tcpxConn_[H]) isBroken() bool { return c.broken.Load() }

func (c *tcpxConn_[H]) SetReadDeadline() error {
	if deadline := time.Now().Add(c.holder.ReadTimeout()); deadline.Sub(c.lastRead) >= time.Second {
		if err := c.netConn.SetReadDeadline(deadline); err != nil {
			return err
		}
		c.lastRead = deadline
	}
	return nil
}
func (c *tcpxConn_[H]) SetWriteDeadline() error {
	if deadline := time.Now().Add(c.holder.WriteTimeout()); deadline.Sub(c.lastWrite) >= time.Second {
		if err := c.netConn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		c.lastWrite = deadline
	}
	return nil
}

func (c *tcpxConn_[H]) Recv() (data []byte, err error) {
	n, err := c.netConn.Read(c.input)
	data = c.input[:n]
	return
}
func (c *tcpxConn_[H]) Send(data []byte) (err error) {
	_, err = c.netConn.Write(data)
	return
}
func (c *tcpxConn_[H]) SendVector() (err error) {
	_, err = c.Vector.WriteTo(c.netConn)
	return
}
