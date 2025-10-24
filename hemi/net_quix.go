// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// QUIX (QUIC over UDP/UDS) Network implementation. See RFC 8999, RFC 9000, RFC 9001, and RFC 9002.

package hemi

import (
	"errors"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/diogin/gorox/hemi/library/gotcp2"
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
	varValue := conn.riskyVariable(c.varCode, c.varName)
	return c.matcher(c, conn, varValue)
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

////////////////////////////////////////////////////////////////

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

////////////////////////////////////////////////////////////////

// QUIXRouter
type QUIXRouter struct {
	// Parent
	router_[*quixGate]
	// Mixins
	_quixHolder_ // to carry configs used by gates
	// Assocs
	dealets compDict[QUIXDealet] // defined dealets. indexed by component name
	cases   []*quixCase          // defined cases. the order must be kept, so we use list. TODO: use ordered map?
	// States
	maxConcurrentConnsPerGate int32 // max concurrent connections allowed per gate
}

func (r *QUIXRouter) onCreate(compName string, stage *Stage) {
	r.router_.onCreate(compName, stage)
	r.dealets = make(compDict[QUIXDealet])
}

func (r *QUIXRouter) OnConfigure() {
	r.router_.onConfigure()
	r._quixHolder_.onConfigure(r)

	// .maxConcurrentConnsPerGate
	r.ConfigureInt32("maxConcurrentConnsPerGate", &r.maxConcurrentConnsPerGate, func(value int32) error {
		if value > 0 {
			return nil
		}
		return errors.New(".maxConcurrentConnsPerGate has an invalid value")
	}, 10000)

	// sub components
	r.dealets.walk(QUIXDealet.OnConfigure)
	for _, kase := range r.cases {
		kase.OnConfigure()
	}
}
func (r *QUIXRouter) OnPrepare() {
	r.router_.onPrepare()
	r._quixHolder_.onPrepare(r)

	// sub components
	r.dealets.walk(QUIXDealet.OnPrepare)
	for _, kase := range r.cases {
		kase.OnPrepare()
	}
}

func (r *QUIXRouter) MaxConcurrentConnsPerGate() int32 { return r.maxConcurrentConnsPerGate }

func (r *QUIXRouter) createDealet(compSign string, compName string) QUIXDealet {
	if _, ok := r.dealets[compName]; ok {
		UseExitln("conflicting dealet with a same component name in router")
	}
	creatorsLock.RLock()
	defer creatorsLock.RUnlock()
	create, ok := quixDealetCreators[compSign]
	if !ok {
		UseExitln("unknown dealet sign: " + compSign)
	}
	dealet := create(compName, r.stage, r)
	dealet.setShell(dealet)
	r.dealets[compName] = dealet
	return dealet
}
func (r *QUIXRouter) createCase(compName string) *quixCase {
	if r.hasCase(compName) {
		UseExitln("conflicting case with a same component name")
	}
	kase := new(quixCase)
	kase.onCreate(compName, r)
	kase.setShell(kase)
	r.cases = append(r.cases, kase)
	return kase
}
func (r *QUIXRouter) hasCase(compName string) bool {
	for _, kase := range r.cases {
		if kase.CompName() == compName {
			return true
		}
	}
	return false
}

func (r *QUIXRouter) Serve() { // runner
	for id := range r.numGates {
		gate := new(quixGate)
		gate.onNew(r, id)
		if err := gate.Open(); err != nil {
			EnvExitln(err.Error())
		}
		r.AddGate(gate)
		go gate.Serve()
	}
	r.WaitGates()

	r.subs.Add(len(r.dealets) + len(r.cases))
	for _, kase := range r.cases {
		go kase.OnShutdown()
	}
	r.dealets.goWalk(QUIXDealet.OnShutdown)
	r.subs.Wait() // dealets, cases

	r.CloseLog()
	if DebugLevel() >= 2 {
		Printf("quixRouter=%s done\n", r.CompName())
	}
	r.stage.DecRouter()
}

func (r *QUIXRouter) quixHolder() _quixHolder_ { return r._quixHolder_ }

func (r *QUIXRouter) serveConn(conn *QUIXConn) { // runner
	for _, kase := range r.cases {
		if !kase.isMatch(conn) {
			continue
		}
		if dealt := kase.execute(conn); dealt {
			break
		}
	}
	putQUIXConn(conn)
}

// quixGate is an opening gate of QUIXRouter.
type quixGate struct {
	// Parent
	Gate_[*QUIXRouter]
	// Mixins
	_quixHolder_
	// States
	maxConcurrentConns int32            // max concurrent conns allowed for this gate
	concurrentConns    atomic.Int32     // TODO: false sharing
	listener           *gotcp2.Listener // the real gate. set after open
}

func (g *quixGate) onNew(router *QUIXRouter, id int32) {
	g.Gate_.OnNew(router, id)
	g._quixHolder_ = router.quixHolder()
	g.maxConcurrentConns = router.MaxConcurrentConnsPerGate()
	g.concurrentConns.Store(0)
}

func (g *quixGate) DecConcurrentConns() int32 { return g.concurrentConns.Add(-1) }
func (g *quixGate) IncConcurrentConns() int32 { return g.concurrentConns.Add(1) }
func (g *quixGate) ReachLimit(concurrentConns int32) bool {
	return concurrentConns > g.maxConcurrentConns
}

func (g *quixGate) Open() error {
	// TODO
	// set g.listener
	return nil
}
func (g *quixGate) Shut() error {
	g.MarkShut()
	return g.listener.Close() // breaks serveXXX()
}

func (g *quixGate) Serve() { // runner
	if g.UDSMode() {
		g.serveUDS()
	} else {
		g.serveTLS()
	}
}
func (g *quixGate) serveUDS() {
	// TODO
}
func (g *quixGate) serveTLS() {
	// TODO
	for !g.IsShut() {
		time.Sleep(time.Second)
	}
	g.server.DecGate()
}

func (g *quixGate) justClose(quicConn *gotcp2.Conn) {
	quicConn.Close()
	g.DecConn()
}

// QUIXConn is a QUIX connection coming from QUIXRouter.
type QUIXConn struct {
	// Parent
	quixConn_[*quixGate]
	// Conn states (stocks)
	// Conn states (controlled)
	// Conn states (non-zeros)
	// Conn states (zeros)
}

var poolQUIXConn sync.Pool

func getQUIXConn(id int64, gate *quixGate, quicConn *gotcp2.Conn) *QUIXConn {
	var conn *QUIXConn
	if x := poolQUIXConn.Get(); x == nil {
		conn = new(QUIXConn)
	} else {
		conn = x.(*QUIXConn)
	}
	conn.onGet(id, gate, quicConn)
	return conn
}
func putQUIXConn(conn *QUIXConn) {
	conn.onPut()
	poolQUIXConn.Put(conn)
}

func (c *QUIXConn) onGet(id int64, gate *quixGate, quicConn *gotcp2.Conn) {
	c.quixConn_.onGet(id, gate, quicConn)
}
func (c *QUIXConn) onPut() {
	c.quixConn_.onPut()
}

func (c *QUIXConn) closeConn() error {
	// TODO
	return nil
}

func (c *QUIXConn) riskyVariable(varCode int16, varName string) (varValue []byte) {
	return quixConnVariables[varCode](c)
}

// quixConnVariables
var quixConnVariables = [...]func(*QUIXConn) []byte{ // keep sync with varCodes
	// TODO
	0: nil, // srcHost
	1: nil, // srcPort
	2: nil, // udsMode
	3: nil, // tlsMode
}

// QUIXStream
type QUIXStream struct {
	// Parent
	quixStream_
	// Assocs
	conn *QUIXConn
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolQUIXStream sync.Pool

func getQUIXStream(conn *QUIXConn, quicStream *gotcp2.Stream) *QUIXStream {
	var stream *QUIXStream
	if x := poolQUIXStream.Get(); x == nil {
		stream = new(QUIXStream)
	} else {
		stream = x.(*QUIXStream)
	}
	stream.onUse(conn, quicStream)
	return stream
}
func putQUIXStream(stream *QUIXStream) {
	stream.onEnd()
	poolQUIXStream.Put(stream)
}

func (s *QUIXStream) onUse(conn *QUIXConn, quicStream *gotcp2.Stream) {
	s.quixStream_.onUse(quicStream)
	s.conn = conn
}
func (s *QUIXStream) onEnd() {
	s.conn = nil
	s.quixStream_.onEnd()
}

func (s *QUIXStream) Write(src []byte) (n int, err error) {
	// TODO
	return
}
func (s *QUIXStream) Read(dst []byte) (n int, err error) {
	// TODO
	return
}

////////////////////////////////////////////////////////////////

func init() {
	RegisterBackend("quixBackend", func(compName string, stage *Stage) Backend {
		b := new(QUIXBackend)
		b.onCreate(compName, stage)
		return b
	})
}

// QUIXBackend component.
type QUIXBackend struct {
	// Parent
	Backend_[*quixNode]
	// States
}

func (b *QUIXBackend) onCreate(compName string, stage *Stage) {
	b.Backend_.OnCreate(compName, stage)
}

func (b *QUIXBackend) OnConfigure() {
	b.Backend_.OnConfigure()
	b.ConfigureNodes()
}
func (b *QUIXBackend) OnPrepare() {
	b.Backend_.OnPrepare()
	b.PrepareNodes()
}

func (b *QUIXBackend) CreateNode(compName string) Node {
	node := new(quixNode)
	node.onCreate(compName, b.stage, b)
	b.AddNode(node)
	return node
}

func (b *QUIXBackend) DialStream() (*QStream, error) {
	node := b.nodes[b.nodeIndexGet()]
	return node.dialStream()
}

// quixNode is a node in QUIXBackend.
type quixNode struct {
	// Parent
	Node_[*QUIXBackend]
	// Mixins
	_quixHolder_
	// States
}

func (n *quixNode) onCreate(compName string, stage *Stage, backend *QUIXBackend) {
	n.Node_.OnCreate(compName, stage, backend)
}

func (n *quixNode) OnConfigure() {
	n.Node_.OnConfigure()
	n._quixHolder_.onConfigure(n)
}
func (n *quixNode) OnPrepare() {
	n.Node_.OnPrepare()
	n._quixHolder_.onPrepare(n)
}

func (n *quixNode) Maintain() { // runner
	n.LoopRun(time.Second, func(now time.Time) {
		// TODO: health check, markDown, markUp()
	})
	// TODO: wait for all conns
	if DebugLevel() >= 2 {
		Printf("quixNode=%s done\n", n.compName)
	}
	n.backend.DecNode()
}

func (n *quixNode) dialStream() (*QStream, error) {
	// Note: A QConn can be used concurrently, limited by maxConcurrentStreams.
	// TODO
	return nil, nil
}
func (n *quixNode) _dialUDS() (*QConn, error) {
	// TODO. note: use n.IncConn()?
	return nil, nil
}
func (n *quixNode) _dialTLS() (*QConn, error) {
	// TODO. note: use n.IncConn()?
	return nil, nil
}

// QConn is a backend-side quix connection to quixNode.
type QConn struct {
	// Parent
	quixConn_[*quixNode]
	// Conn states (stocks)
	// Conn states (controlled)
	// Conn states (non-zeros)
	// Conn states (zeros)
}

var poolQConn sync.Pool

func getQConn(id int64, node *quixNode, quicConn *gotcp2.Conn) *QConn {
	var conn *QConn
	if x := poolQConn.Get(); x == nil {
		conn = new(QConn)
	} else {
		conn = x.(*QConn)
	}
	conn.onGet(id, node, quicConn)
	return conn
}
func putQConn(conn *QConn) {
	conn.onPut()
	poolQConn.Put(conn)
}

func (c *QConn) onGet(id int64, node *quixNode, quicConn *gotcp2.Conn) {
	c.quixConn_.onGet(id, node, quicConn)
}
func (c *QConn) onPut() {
	c.quixConn_.onPut()
}

func (c *QConn) ranOut() bool {
	return c.cumulativeStreams.Add(1) > c.holder.MaxCumulativeStreamsPerConn()
}
func (c *QConn) DialStream() (*QStream, error) {
	// Note: A QConn can be used concurrently, limited by maxConcurrentStreams.
	// TODO: qStream.onUse()
	return nil, nil
}

func (c *QConn) Close() error {
	quicConn := c.quicConn
	putQConn(c)
	return quicConn.Close()
}

// QStream is a bidirectional stream of QConn.
type QStream struct {
	// Parent
	quixStream_
	// Assocs
	conn *QConn
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolQStream sync.Pool

func getQStream(conn *QConn, quicStream *gotcp2.Stream) *QStream {
	var stream *QStream
	if x := poolQStream.Get(); x == nil {
		stream = new(QStream)
	} else {
		stream = x.(*QStream)
	}
	stream.onUse(conn, quicStream)
	return stream
}
func putQStream(stream *QStream) {
	stream.onEnd()
	poolQStream.Put(stream)
}

func (s *QStream) onUse(conn *QConn, quicStream *gotcp2.Stream) {
	s.quixStream_.onUse(quicStream)
	s.conn = conn
}
func (s *QStream) onEnd() {
	s.conn = nil
	s.quixStream_.onEnd()
}

func (s *QStream) Write(src []byte) (n int, err error) {
	// TODO
	return
}
func (s *QStream) Read(dst []byte) (n int, err error) {
	// TODO
	return
}

func (s *QStream) Close() error {
	// TODO
	return nil
}
