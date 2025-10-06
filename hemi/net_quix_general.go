// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// QUIX (QUIC over UDP/UDS) types. See RFC 8999, RFC 9000, RFC 9001, and RFC 9002.

package hemi

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/diogin/gorox/hemi/library/gotcp2"
)

// quixHolder
type quixHolder interface {
	// Imports
	holder
	// Methods
	MaxCumulativeStreamsPerConn() int32
	MaxConcurrentStreamsPerConn() int32
}

// _quixHolder_ is a mixin.
type _quixHolder_ struct { // for quixNode, QUIXRouter, and QUIXGate
	// States
	maxCumulativeStreamsPerConn int32 // max cumulative streams of one conn. 0 means infinite
	maxConcurrentStreamsPerConn int32 // max concurrent streams of one conn
}

func (h *_quixHolder_) onConfigure(comp Component) {
	// .maxCumulativeStreamsPerConn
	comp.ConfigureInt32("maxCumulativeStreamsPerConn", &h.maxCumulativeStreamsPerConn, func(value int32) error {
		if value >= 0 {
			return nil
		}
		return errors.New(".maxCumulativeStreamsPerConn has an invalid value")
	}, 1000)

	// .maxConcurrentStreamsPerConn
	comp.ConfigureInt32("maxConcurrentStreamsPerConn", &h.maxConcurrentStreamsPerConn, func(value int32) error {
		if value >= 0 {
			return nil
		}
		return errors.New(".maxConcurrentStreamsPerConn has an invalid value")
	}, 1000)
}
func (h *_quixHolder_) onPrepare(comp Component) {
}

func (h *_quixHolder_) MaxCumulativeStreamsPerConn() int32 { return h.maxCumulativeStreamsPerConn }
func (h *_quixHolder_) MaxConcurrentStreamsPerConn() int32 { return h.maxConcurrentStreamsPerConn }

// quixConn collects shared methods between *QUIXConn and *QConn.
type quixConn interface {
	ID() int64
	Holder() quixHolder
	UDSMode() bool
	TLSMode() bool
	MakeTempName(dst []byte, unixTime int64) int
	markBroken()
	isBroken() bool
}

// quixConn_ is a parent.
type quixConn_[H quixHolder] struct { // for QUIXConn and QConn
	// Conn states (stocks)
	// Conn states (controlled)
	// Conn states (non-zeros)
	id       int64        // the conn id
	holder   H            // quixNode or quixGate
	quicConn *gotcp2.Conn // the underlying conn
	// Conn states (zeros)
	counter           atomic.Int64 // can be used to generate a random number
	lastRead          time.Time    // deadline of last read operation
	lastWrite         time.Time    // deadline of last write operation
	broken            atomic.Bool  // is connection broken?
	cumulativeStreams atomic.Int32 // how many streams have been used?
	concurrentStreams atomic.Int32 // how many concurrent streams?
}

func (c *quixConn_[H]) onGet(id int64, holder H, quicConn *gotcp2.Conn) {
	c.id = id
	c.holder = holder
	c.quicConn = quicConn
}
func (c *quixConn_[H]) onPut() {
	var null H // nil
	c.holder = null
	c.quicConn = nil
	c.counter.Store(0)
	c.lastRead = time.Time{}
	c.lastWrite = time.Time{}
	c.broken.Store(false)
	c.cumulativeStreams.Store(0)
	c.concurrentStreams.Store(0)
}

func (c *quixConn_[H]) ID() int64 { return c.id }

func (c *quixConn_[H]) Holder() quixHolder { return c.holder }

func (c *quixConn_[H]) UDSMode() bool { return c.holder.UDSMode() }
func (c *quixConn_[H]) TLSMode() bool { return c.holder.TLSMode() }

func (c *quixConn_[H]) MakeTempName(dst []byte, unixTime int64) int {
	return makeTempName(dst, c.holder.Stage().ID(), unixTime, c.id, c.counter.Add(1))
}

func (c *quixConn_[H]) markBroken()    { c.broken.Store(true) }
func (c *quixConn_[H]) isBroken() bool { return c.broken.Load() }

// quixStream collects shared methods between *QUIXStream and *QStream.
type quixStream interface {
	// TODO
}

// quixStream_ is a parent.
type quixStream_ struct { // for QUIXStream and QStream
	// Stream states (stocks)
	stockBuffer [256]byte // a (fake) buffer to workaround Go's conservative escape analysis
	// Stream states (controlled)
	// Stream states (non-zeros)
	quicStream *gotcp2.Stream
	// Stream states (zeros)
}

func (s *quixStream_) onUse(quicStream *gotcp2.Stream) {
	s.quicStream = quicStream
}
func (s *quixStream_) onEnd() {
	s.quicStream = nil
}
