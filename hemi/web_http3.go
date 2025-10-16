// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// HTTP/3 implementation. See RFC 9114, RFC 9204, and RFC 9220.

// Server Push is not supported because it's rarely used. Chrome and Firefox even removed it.

package hemi

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/diogin/gorox/hemi/library/gotcp2"
)

func init() {
	RegisterServer("http3Server", func(compName string, stage *Stage) Server {
		s := new(http3Server)
		s.onCreate(compName, stage)
		return s
	})
}

// http3Server is the HTTP/3 server. An http3Server has many http3Gates.
type http3Server struct {
	// Parent
	httpServer_[*http3Gate]
	// States
}

func (s *http3Server) onCreate(compName string, stage *Stage) {
	s.httpServer_.onCreate(compName, stage)
	s.tlsConfig = new(tls.Config) // currently tls mode is always enabled in http/3
}

func (s *http3Server) OnConfigure() {
	s.httpServer_.onConfigure()
}
func (s *http3Server) OnPrepare() {
	s.httpServer_.onPrepare()
}

func (s *http3Server) Serve() { // runner
	for id := range s.numGates {
		gate := new(http3Gate)
		gate.onNew(s, id)
		if err := gate.Open(); err != nil {
			EnvExitln(err.Error())
		}
		s.AddGate(gate)
		go gate.Serve()
	}
	s.WaitGates()
	if DebugLevel() >= 2 {
		Printf("http3Server=%s done\n", s.CompName())
	}
	s.stage.DecServer()
}

// http3Gate is a gate of http3Server.
type http3Gate struct {
	// Parent
	httpGate_[*http3Server]
	// States
	listener *gotcp2.Listener // the real gate. set after open
}

func (g *http3Gate) onNew(server *http3Server, id int32) {
	g.httpGate_.onNew(server, id)
}

func (g *http3Gate) Open() error {
	// TODO: udsMode or tlsMode?
	listener := gotcp2.NewListener(g.Address())
	if err := listener.Open(); err != nil {
		return err
	}
	g.listener = listener
	return nil
}
func (g *http3Gate) Shut() error {
	g.MarkShut()
	return g.listener.Close() // breaks serveXXX()
}

func (g *http3Gate) Serve() { // runner
	if g.UDSMode() {
		g.serveUDS()
	} else {
		g.serveTLS()
	}
}
func (g *http3Gate) serveUDS() {
	// TODO
}
func (g *http3Gate) serveTLS() {
	connID := int64(1)
	for {
		quicConn, err := g.listener.Accept()
		if err != nil {
			if g.IsShut() {
				break
			} else {
				continue
			}
		}
		g.IncConn()
		if concurrentConns := g.IncConcurrentConns(); g.ReachLimit(concurrentConns) {
			g.justClose(quicConn)
			continue
		}
		server3Conn := getServer3Conn(connID, g, quicConn)
		go server3Conn.serve() // server3Conn will be put to pool in serve()
		connID++
	}
	g.WaitConns() // TODO: max timeout?
	if DebugLevel() >= 2 {
		Printf("http3Gate=%d done\n", g.id)
	}
	g.server.DecGate()
}

func (g *http3Gate) justClose(quicConn *gotcp2.Conn) {
	quicConn.Close()
	g.DecConcurrentConns()
	g.DecConn()
}

// server3Conn is the server-side HTTP/3 connection.
type server3Conn struct {
	// Parent
	http3Conn_[*http3Gate, *server3Stream]
	// Mixins
	// Conn states (stocks)
	// Conn states (controlled)
	// Conn states (non-zeros)
	// Conn states (zeros)
}

var poolServer3Conn sync.Pool

func getServer3Conn(id int64, gate *http3Gate, quicConn *gotcp2.Conn) *server3Conn {
	var servConn *server3Conn
	if x := poolServer3Conn.Get(); x == nil {
		servConn = new(server3Conn)
	} else {
		servConn = x.(*server3Conn)
	}
	servConn.onGet(id, gate, quicConn)
	return servConn
}
func putServer3Conn(servConn *server3Conn) {
	servConn.onPut()
	poolServer3Conn.Put(servConn)
}

func (c *server3Conn) onGet(id int64, gate *http3Gate, quicConn *gotcp2.Conn) {
	c.http3Conn_.onGet(id, gate, quicConn)
}
func (c *server3Conn) onPut() {
	c.http3Conn_.onPut()
}

func (c *server3Conn) serve() { // runner
	// TODO
}

func (c *server3Conn) closeConn() {
	c.quicConn.Close()
	c.holder.DecConcurrentConns()
	c.holder.DecConn()
}

// server3Stream is the server-side HTTP/3 stream.
type server3Stream struct {
	// Parent
	http3Stream_[*server3Conn]
	// Mixins
	// Assocs
	request  server3Request  // the http/3 request.
	response server3Response // the http/3 response.
	socket   *server3Socket  // ...
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolServer3Stream sync.Pool

func getServer3Stream(conn *server3Conn, quicStream *gotcp2.Stream) *server3Stream {
	var servStream *server3Stream
	if x := poolServer3Stream.Get(); x == nil {
		servStream = new(server3Stream)
		servReq, servResp := &servStream.request, &servStream.response
		servReq.stream = servStream
		servReq.in = servReq
		servResp.stream = servStream
		servResp.out = servResp
		servResp.request = servReq
	} else {
		servStream = x.(*server3Stream)
	}
	servStream.onUse(conn, quicStream)
	return servStream
}
func putServer3Stream(servStream *server3Stream) {
	servStream.onEnd()
	poolServer3Stream.Put(servStream)
}

func (s *server3Stream) onUse(conn *server3Conn, quicStream *gotcp2.Stream) { // for non-zeros
	s.http3Stream_.onUse(conn, quicStream)

	s.request.onUse()
	s.response.onUse()
}
func (s *server3Stream) onEnd() { // for zeros
	s.response.onEnd()
	s.request.onEnd()
	if s.socket != nil {
		s.socket.onEnd()
		s.socket = nil
	}

	s.http3Stream_.onEnd()
}

func (s *server3Stream) execute() { // runner
	// TODO ...
	putServer3Stream(s)
}
func (s *server3Stream) _serveAbnormal(req *server3Request, resp *server3Response) { // 4xx & 5xx
	// TODO
	// s.setWriteDeadline() // for _serveAbnormal
	// s.writeVec()
}
func (s *server3Stream) _writeContinue() bool { // 100 continue
	// TODO
	// s.setWriteDeadline() // for _writeContinue
	// s.write()
	return false
}

func (s *server3Stream) executeExchan(webapp *Webapp, req *server3Request, resp *server3Response) { // request & response
	// TODO
	webapp.dispatchExchan(req, resp)
}
func (s *server3Stream) executeSocket() { // see RFC 9220
	// TODO
}

// server3Request is the server-side HTTP/3 request.
type server3Request struct { // incoming. needs parsing
	// Parent
	serverRequest_
	// Assocs
	in3 _http3In_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *server3Request) onUse() {
	r.serverRequest_.onUse(Version3)
	r.in3.onUse(&r._httpIn_)
}
func (r *server3Request) onEnd() {
	r.serverRequest_.onEnd()
	r.in3.onEnd()
}

func (r *server3Request) recvHead() {
	// TODO
	// r.stream.setReadDeadline() // the entire request head must be received in one read timeout
}

func (r *server3Request) readContent() (data []byte, err error) { return r.in3.readContent() }

// server3Response is the server-side HTTP/3 response.
type server3Response struct { // outgoing. needs building
	// Parent
	serverResponse_
	// Assocs
	out3 _http3Out_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *server3Response) onUse() {
	r.serverResponse_.onUse(Version3)
	r.out3.onUse(&r._httpOut_)
}
func (r *server3Response) onEnd() {
	r.serverResponse_.onEnd()
	r.out3.onEnd()
}

func (r *server3Response) addHeader(name []byte, value []byte) bool {
	return r.out3.addHeader(name, value)
}
func (r *server3Response) header(name []byte) (value []byte, ok bool) { return r.out3.header(name) }
func (r *server3Response) hasHeader(name []byte) bool                 { return r.out3.hasHeader(name) }
func (r *server3Response) delHeader(name []byte) (deleted bool)       { return r.out3.delHeader(name) }
func (r *server3Response) delHeaderAt(i uint8)                        { r.out3.delHeaderAt(i) }

func (r *server3Response) AddHTTPSRedirection(authority string) bool {
	// TODO
	return false
}
func (r *server3Response) AddHostnameRedirection(hostname string) bool {
	// TODO
	return false
}
func (r *server3Response) AddDirectoryRedirection() bool {
	// TODO
	return false
}

func (r *server3Response) AddCookie(cookie *Cookie) bool {
	// TODO
	return false
}

func (r *server3Response) sendChain() error { return r.out3.sendChain() }

func (r *server3Response) echoHeaders() error { return r.out3.writeHeaders() }
func (r *server3Response) echoChain() error   { return r.out3.echoChain() }

func (r *server3Response) addTrailer(name []byte, value []byte) bool {
	return r.out3.addTrailer(name, value)
}
func (r *server3Response) trailer(name []byte) (value []byte, ok bool) { return r.out3.trailer(name) }

func (r *server3Response) proxyPass1xx(backResp BackendResponse) bool {
	backResp.proxyDelHopHeaderFields()
	r.status = backResp.Status()
	if !backResp.proxyWalkHeaderLines(r, func(out httpOut, headerLine *pair, headerName []byte, lineValue []byte) bool {
		return out.insertHeader(headerLine.nameHash, headerName, lineValue) // some header fields (e.g. "connection") are restricted
	}) {
		return false
	}
	// TODO
	// For next use.
	r.onEnd()
	r.onUse()
	return false
}
func (r *server3Response) proxyPassHeaders() error          { return r.out3.writeHeaders() }
func (r *server3Response) proxyPassBytes(data []byte) error { return r.out3.proxyPassBytes(data) }

func (r *server3Response) finalizeHeaders() { // add at most 256 bytes
	// TODO
	/*
		// date: Sun, 06 Nov 1994 08:49:37 GMT
		if r.iDate == 0 {
			clock := r.stream.(*server3Stream).conn.gate.stage.clock
			r.outputEdge += uint16(clock.writeDate3(r.output[r.outputEdge:]))
		}
	*/
}
func (r *server3Response) finalizeVague() error {
	// TODO
	return nil
}

func (r *server3Response) addedHeaders() []byte { return nil }
func (r *server3Response) fixedHeaders() []byte { return nil }

// server3Socket is the server-side HTTP/3 webSocket.
type server3Socket struct { // incoming and outgoing
	// Parent
	serverSocket_
	// Assocs
	so3 _http3Socket_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolServer3Socket sync.Pool

func getServer3Socket(stream *server3Stream) *server3Socket {
	// TODO
	return nil
}
func putServer3Socket(socket *server3Socket) {
	// TODO
}

func (s *server3Socket) onUse() {
	s.serverSocket_.onUse()
	s.so3.onUse(&s._httpSocket_)
}
func (s *server3Socket) onEnd() {
	s.serverSocket_.onEnd()
	s.so3.onEnd()
}

func (s *server3Socket) serverTodo3() {
	s.serverTodo()
	s.so3.todo3()
}

////////////////////////////////////////////////////////////////

func init() {
	RegisterBackend("http3Backend", func(compName string, stage *Stage) Backend {
		b := new(HTTP3Backend)
		b.OnCreate(compName, stage)
		return b
	})
}

// HTTP3Backend
type HTTP3Backend struct {
	// Parent
	httpBackend_[*http3Node]
	// States
}

func (b *HTTP3Backend) CreateNode(compName string) Node {
	node := new(http3Node)
	node.onCreate(compName, b.stage, b)
	b.AddNode(node)
	return node
}

func (b *HTTP3Backend) AcquireStream(servReq ServerRequest) (BackendStream, error) {
	return b.nodes[b.nodeIndexGet()].fetchStream()
}
func (b *HTTP3Backend) ReleaseStream(backStream BackendStream) {
	backStream3 := backStream.(*backend3Stream)
	backStream3.conn.holder.storeStream(backStream3)
}

// http3Node
type http3Node struct {
	// Parent
	httpNode_[*HTTP3Backend, *backend3Conn]
	// States
}

func (n *http3Node) onCreate(compName string, stage *Stage, backend *HTTP3Backend) {
	n.httpNode_.onCreate(compName, stage, backend)
}

func (n *http3Node) OnConfigure() {
	n.httpNode_.onConfigure()
	if n.tlsMode {
		n.tlsConfig.InsecureSkipVerify = true
	}
}
func (n *http3Node) OnPrepare() {
	n.httpNode_.onPrepare()
}

func (n *http3Node) Maintain() { // runner
	n.LoopRun(time.Second, func(now time.Time) {
		// TODO: health check, markDown, markUp()
	})
	// TODO: wait for all conns
	if DebugLevel() >= 2 {
		Printf("http3Node=%s done\n", n.compName)
	}
	n.backend.DecNode()
}

func (n *http3Node) fetchStream() (*backend3Stream, error) {
	// TODO
	return nil, nil
}
func (n *http3Node) _dialUDS() (*backend3Conn, error) {
	// TODO
	return nil, nil
}
func (n *http3Node) _dialTLS() (*backend3Conn, error) {
	// TODO
	return nil, nil
}
func (n *http3Node) storeStream(backStream *backend3Stream) {
	// TODO
}

// backend3Conn is the backend-side HTTP/3 connection.
type backend3Conn struct {
	// Parent
	http3Conn_[*http3Node, *backend3Stream]
	// Mixins
	// Assocs
	// Conn states (stocks)
	// Conn states (controlled)
	expireTime time.Time // when the conn is considered expired
	// Conn states (non-zeros)
	// Conn states (zeros)
}

var poolBackend3Conn sync.Pool

func getBackend3Conn(id int64, node *http3Node, quicConn *gotcp2.Conn) *backend3Conn {
	var backConn *backend3Conn
	if x := poolBackend3Conn.Get(); x == nil {
		backConn = new(backend3Conn)
	} else {
		backConn = x.(*backend3Conn)
	}
	backConn.onGet(id, node, quicConn)
	return backConn
}
func putBackend3Conn(backConn *backend3Conn) {
	backConn.onPut()
	poolBackend3Conn.Put(backConn)
}

func (c *backend3Conn) onGet(id int64, node *http3Node, quicConn *gotcp2.Conn) {
	c.http3Conn_.onGet(id, node, quicConn)
}
func (c *backend3Conn) onPut() {
	c.expireTime = time.Time{}
	c.http3Conn_.onPut()
}

func (c *backend3Conn) isAlive() bool {
	return c.expireTime.IsZero() || time.Now().Before(c.expireTime)
}

func (c *backend3Conn) newStream() (*backend3Stream, error) { // used by http3Node
	// Note: A backend3Conn can be used concurrently, limited by maxConcurrentStreams.
	// TODO: backStream.onUse()
	return nil, nil
}
func (c *backend3Conn) delStream(backStream *backend3Stream) { // used by http3Node
	// Note: A backend3Conn can be used concurrently, limited by maxConcurrentStreams.
	// TODO
	//backStream.onEnd()
}

func (c *backend3Conn) Close() error {
	quicConn := c.quicConn
	putBackend3Conn(c)
	return quicConn.Close()
}

// backend3Stream is the backend-side HTTP/3 stream.
type backend3Stream struct {
	// Parent
	http3Stream_[*backend3Conn]
	// Mixins
	// Assocs
	response backend3Response // the backend-side http/3 response
	request  backend3Request  // the backend-side http/3 request
	socket   *backend3Socket  // the backend-side http/3 webSocket
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolBackend3Stream sync.Pool

func getBackend3Stream(conn *backend3Conn, quicStream *gotcp2.Stream) *backend3Stream {
	var backStream *backend3Stream
	if x := poolBackend3Stream.Get(); x == nil {
		backStream = new(backend3Stream)
		backResp, backReq := &backStream.response, &backStream.request
		backResp.stream = backStream
		backResp.in = backResp
		backReq.stream = backStream
		backReq.out = backReq
		backReq.response = backResp
	} else {
		backStream = x.(*backend3Stream)
	}
	backStream.onUse(conn, quicStream)
	return backStream
}
func putBackend3Stream(backStream *backend3Stream) {
	backStream.onEnd()
	poolBackend3Stream.Put(backStream)
}

func (s *backend3Stream) onUse(conn *backend3Conn, quicStream *gotcp2.Stream) { // for non-zeros
	s.http3Stream_.onUse(conn, quicStream)

	s.response.onUse()
	s.request.onUse()
}
func (s *backend3Stream) onEnd() { // for zeros
	s.request.onEnd()
	s.response.onEnd()
	if s.socket != nil {
		s.socket.onEnd()
		s.socket = nil
	}

	s.http3Stream_.onEnd()
}

func (s *backend3Stream) Response() BackendResponse { return &s.response }
func (s *backend3Stream) Request() BackendRequest   { return &s.request }
func (s *backend3Stream) Socket() BackendSocket     { return nil } // TODO. See RFC 9220

// backend3Response is the backend-side HTTP/3 response.
type backend3Response struct { // incoming. needs parsing
	// Parent
	backendResponse_
	// Assocs
	in3 _http3In_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *backend3Response) onUse() {
	r.backendResponse_.onUse(Version3)
	r.in3.onUse(&r._httpIn_)
}
func (r *backend3Response) onEnd() {
	r.backendResponse_.onEnd()
	r.in3.onEnd()
}

func (r *backend3Response) recvHead() { // control data + header section
	// TODO
	// r.stream.setReadDeadline() // the entire response head must be received in one read timeout
}

func (r *backend3Response) readContent() (data []byte, err error) { return r.in3.readContent() }

// backend3Request is the backend-side HTTP/3 request.
type backend3Request struct { // outgoing. needs building
	// Parent
	backendRequest_
	// Assocs
	out3 _http3Out_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *backend3Request) onUse() {
	r.backendRequest_.onUse(Version3)
	r.out3.onUse(&r._httpOut_)
}
func (r *backend3Request) onEnd() {
	r.backendRequest_.onEnd()
	r.out3.onEnd()
}

func (r *backend3Request) addHeader(name []byte, value []byte) bool {
	return r.out3.addHeader(name, value)
}
func (r *backend3Request) header(name []byte) (value []byte, ok bool) { return r.out3.header(name) }
func (r *backend3Request) hasHeader(name []byte) bool                 { return r.out3.hasHeader(name) }
func (r *backend3Request) delHeader(name []byte) (deleted bool)       { return r.out3.delHeader(name) }
func (r *backend3Request) delHeaderAt(i uint8)                        { r.out3.delHeaderAt(i) }

func (r *backend3Request) AddCookie(name string, value string) bool {
	// TODO. need some space to place the cookie
	return false
}
func (r *backend3Request) proxyCopyCookies(servReq ServerRequest) bool { // NOTE: DO NOT merge into one "cookie" header field!
	// TODO: one by one?
	return true
}

func (r *backend3Request) sendChain() error { return r.out3.sendChain() }

func (r *backend3Request) echoHeaders() error { return r.out3.writeHeaders() }
func (r *backend3Request) echoChain() error   { return r.out3.echoChain() }

func (r *backend3Request) addTrailer(name []byte, value []byte) bool {
	return r.out3.addTrailer(name, value)
}
func (r *backend3Request) trailer(name []byte) (value []byte, ok bool) { return r.out3.trailer(name) }

func (r *backend3Request) proxySetMethodURI(method []byte, uri []byte, hasContent bool) bool { // :method = method, :path = uri
	// TODO: set :method and :path
	return false
}
func (r *backend3Request) proxySetAuthority(hostname []byte, colonport []byte) bool {
	// TODO: set :authority
	return false
}

func (r *backend3Request) proxyPassHeaders() error          { return r.out3.writeHeaders() }
func (r *backend3Request) proxyPassBytes(data []byte) error { return r.out3.proxyPassBytes(data) }

func (r *backend3Request) finalizeHeaders() { // add at most 256 bytes
	// TODO
}
func (r *backend3Request) finalizeVague() error {
	// TODO
	return nil
}

func (r *backend3Request) addedHeaders() []byte { return nil } // TODO
func (r *backend3Request) fixedHeaders() []byte { return nil } // TODO

// backend3Socket is the backend-side HTTP/3 webSocket.
type backend3Socket struct { // incoming and outgoing
	// Parent
	backendSocket_
	// Assocs
	so3 _http3Socket_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolBackend3Socket sync.Pool

func getBackend3Socket(stream *backend3Stream) *backend3Socket {
	// TODO
	return nil
}
func putBackend3Socket(socket *backend3Socket) {
	// TODO
}

func (s *backend3Socket) onUse() {
	s.backendSocket_.onUse()
	s.so3.onUse(&s._httpSocket_)
}
func (s *backend3Socket) onEnd() {
	s.backendSocket_.onEnd()
	s.so3.onEnd()
}

func (s *backend3Socket) backendTodo3() {
	s.backendTodo()
	s.so3.todo3()
}

////////////////////////////////////////////////////////////////

// http3Conn
type http3Conn interface { // for *backend3Conn and *server3Conn
	// Imports
	httpConn
	// Methods
}

// http3Conn_ is a parent.
type http3Conn_[H httpHolder, S http3Stream] struct { // for backend3Conn and server3Conn
	// Parent
	httpConn_[H]
	// Conn states (stocks)
	// Conn states (controlled)
	// Conn states (non-zeros)
	quicConn    *gotcp2.Conn // the underlying quic connection
	inBuffer    *http3Buffer // ...
	decodeTable qpackTable   // ...
	encodeTable qpackTable   // ...
	// Conn states (zeros)
	_http3Conn0 // all values in this struct must be zero by default!
}
type _http3Conn0 struct { // for fast reset, entirely
	inBufferEdge uint32 // incoming data ends at c.inBuffer.buf[c.inBufferEdge]
	sectBack     uint32 // incoming frame section (header or payload) begins from c.inBuffer.buf[c.sectBack]
	sectFore     uint32 // incoming frame section (header or payload) ends at c.inBuffer.buf[c.sectFore]
}

func (c *http3Conn_[H, S]) onGet(id int64, holder H, quicConn *gotcp2.Conn) {
	c.httpConn_.onGet(id, holder)

	c.quicConn = quicConn
	if c.inBuffer == nil {
		c.inBuffer = getHTTP3Buffer()
		c.inBuffer.incRef()
	}
}
func (c *http3Conn_[H, S]) onPut() {
	// c.inBuffer is reserved
	// c.decodeTable is reserved
	// c.encodeTable is reserved
	c.quicConn = nil

	c.httpConn_.onPut()
}

func (c *http3Conn_[H, S]) remoteAddr() net.Addr { return nil } // TODO

// http3Stream
type http3Stream interface { // for *backend3Stream and *server3Stream
	// Imports
	httpStream
	// Methods
}

// http3Stream_ is a parent.
type http3Stream_[C http3Conn] struct { // for backend3Stream and server3Stream
	// Parent
	httpStream_[C]
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	quicStream *gotcp2.Stream // the underlying quic stream
	// Stream states (zeros)
	lastWrite     time.Time // deadline of last write operation
	lastRead      time.Time // deadline of last read operation
	_http3Stream0           // all values in this struct must be zero by default!
}
type _http3Stream0 struct { // for fast reset, entirely
}

func (s *http3Stream_[C]) onUse(conn C, quicStream *gotcp2.Stream) {
	s.httpStream_.onUse(conn)

	s.quicStream = quicStream
}
func (s *http3Stream_[C]) onEnd() {
	s._http3Stream0 = _http3Stream0{}

	s.lastRead = time.Time{}
	s.lastWrite = time.Time{}
	s.quicStream = nil
	s.httpStream_.onEnd()
}

func (s *http3Stream_[C]) ID() int64 { return s.quicStream.ID() }

func (s *http3Stream_[C]) markBroken()    {}               // TODO
func (s *http3Stream_[C]) isBroken() bool { return false } // TODO

func (s *http3Stream_[C]) setReadDeadline() error {
	// TODO
	return nil
}
func (s *http3Stream_[C]) setWriteDeadline() error {
	// TODO
	return nil
}

func (s *http3Stream_[C]) read(dst []byte) (int, error)     { return s.quicStream.Read(dst) }
func (s *http3Stream_[C]) readFull(dst []byte) (int, error) { return io.ReadFull(s.quicStream, dst) }
func (s *http3Stream_[C]) write(src []byte) (int, error)    { return s.quicStream.Write(src) }
func (s *http3Stream_[C]) writeVec(srcVec *net.Buffers) (int64, error) {
	return srcVec.WriteTo(s.quicStream)
}

// _http3In_ is a mixin.
type _http3In_ struct { // for backend3Response and server3Request
	// Parent
	*_httpIn_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *_http3In_) onUse(parent *_httpIn_) {
	r._httpIn_ = parent
}
func (r *_http3In_) onEnd() {
	r._httpIn_ = nil
}

func (r *_http3In_) _growHeaders(size int32) bool {
	// TODO
	// use r.input
	return false
}

func (r *_http3In_) readContent() (data []byte, err error) {
	// TODO
	return
}
func (r *_http3In_) _readSizedContent() ([]byte, error) {
	// r.stream.setReadDeadline() // may be called multiple times during the reception of the sized content
	return nil, nil
}
func (r *_http3In_) _readVagueContent() ([]byte, error) {
	// r.stream.setReadDeadline() // may be called multiple times during the reception of the vague content
	return nil, nil
}

// _http3Out_ is a mixin.
type _http3Out_ struct { // for backend3Request and server3Response
	// Parent
	*_httpOut_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *_http3Out_) onUse(parent *_httpOut_) {
	r._httpOut_ = parent
}
func (r *_http3Out_) onEnd() {
	r._httpOut_ = nil
}

func (r *_http3Out_) addHeader(name []byte, value []byte) bool {
	// TODO
	return false
}
func (r *_http3Out_) header(name []byte) (value []byte, ok bool) {
	// TODO
	return
}
func (r *_http3Out_) hasHeader(name []byte) bool {
	// TODO
	return false
}
func (r *_http3Out_) delHeader(name []byte) (deleted bool) {
	// TODO
	return false
}
func (r *_http3Out_) delHeaderAt(i uint8) {
	// TODO
}

func (r *_http3Out_) sendChain() error {
	// TODO
	return nil
}
func (r *_http3Out_) _sendEntireChain() error {
	// TODO
	return nil
}
func (r *_http3Out_) _sendSingleRange() error {
	// TODO
	return nil
}
func (r *_http3Out_) _sendMultiRanges() error {
	// TODO
	return nil
}

func (r *_http3Out_) echoChain() error {
	// TODO
	return nil
}

func (r *_http3Out_) addTrailer(name []byte, value []byte) bool {
	// TODO
	return false
}
func (r *_http3Out_) trailer(name []byte) (value []byte, ok bool) {
	// TODO
	return
}
func (r *_http3Out_) trailers() []byte {
	// TODO
	return nil
}

func (r *_http3Out_) proxyPassBytes(data []byte) error { return r.writeBytes(data) }

func (r *_http3Out_) finalizeVague() error {
	// TODO
	if r.numTrailerFields == 1 { // no trailer section
	} else { // with trailer section
	}
	return nil
}

func (r *_http3Out_) writeHeaders() error { // used by echo and pass
	// TODO
	r.outputEdge = 0 // now that header output are all sent, r.output will be used by trailer fields (if any), so reset it.
	return nil
}
func (r *_http3Out_) writePiece(piece *Piece, vague bool) error {
	// TODO
	return nil
}
func (r *_http3Out_) _writeTextPiece(piece *Piece) error {
	// TODO
	return nil
}
func (r *_http3Out_) _writeFilePiece(piece *Piece) error {
	// TODO
	// r.stream.setWriteDeadline() // for _writeFilePiece
	// r.stream.write() or r.stream.writeVec()
	return nil
}
func (r *_http3Out_) writeVector() error {
	// TODO
	// r.stream.setWriteDeadline() // for writeVector
	// r.stream.writeVec()
	return nil
}
func (r *_http3Out_) writeBytes(data []byte) error {
	// TODO
	// r.stream.setWriteDeadline() // for writeBytes
	// r.stream.write()
	return nil
}

// _http3Socket_ is a mixin.
type _http3Socket_ struct { // for backend3Socket and server3Socket
	// Parent
	*_httpSocket_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (s *_http3Socket_) onUse(parent *_httpSocket_) {
	s._httpSocket_ = parent
}
func (s *_http3Socket_) onEnd() {
	s._httpSocket_ = nil
}

func (s *_http3Socket_) todo3() {
	s.todo()
}

////////////////////////////////////////////////////////////////

const ( // HTTP/3 sizes and limits for both of our HTTP/3 server and HTTP/3 backend
	http3MaxTableSize         = _4K
	http3MaxConcurrentStreams = 127 // currently hardcoded
)

// qpackTableEntry is a QPACK table entry.
type qpackTableEntry struct { // 8 bytes
	nameHash  uint16 // name hash
	nameFrom  uint16 // name edge at nameFrom+nameSize
	nameSize  uint8  // must <= 255
	isStatic  bool   // ...
	valueEdge uint16 // value: [nameFrom+nameSize:valueEdge]
}

var qpackStaticBytes = []byte(":authority:path/age0content-dispositioncontent-length0cookiedateetagif-modified-sinceif-none-matchlast-modifiedlinklocationrefererset-cookie:methodCONNECTDELETEGETHEADOPTIONSPOSTPUT:schemehttphttps:status103200304404503accept*/*application/dns-messageaccept-encodinggzip, deflate, braccept-rangesbytesaccess-control-allow-headerscache-controlcontent-typeaccess-control-allow-origin*cache-controlmax-age=0max-age=2592000max-age=604800no-cacheno-storepublic, max-age=31536000content-encodingbrgzipcontent-typeapplication/dns-messageapplication/javascriptapplication/jsonapplication/x-www-form-urlencodedimage/gifimage/jpegimage/pngtext/csstext/html; charset=utf-8text/plaintext/plain;charset=utf-8rangebytes=0-strict-transport-securitymax-age=31536000max-age=31536000; includesubdomainsmax-age=31536000; includesubdomains; preloadvaryaccept-encodingoriginx-content-type-optionsnosniffx-xss-protection1; mode=block:status100204206302400403421425500accept-languageaccess-control-allow-credentialsFALSETRUEaccess-control-allow-headers*access-control-allow-methodsgetget, post, optionsoptionsaccess-control-expose-headerscontent-lengthaccess-control-request-headerscontent-typeaccess-control-request-methodgetpostalt-svcclearauthorizationcontent-security-policyscript-src 'none'; object-src 'none'; base-uri 'none'early-data1expect-ctforwardedif-rangeoriginpurposeprefetchservertiming-allow-origin*upgrade-insecure-requests1user-agentx-forwarded-forx-frame-optionsdenysameorigin") // DO NOT CHANGE THIS UNLESS YOU KNOW WHAT YOU ARE DOING

// qpackStaticTable
var qpackStaticTable = [...]qpackTableEntry{ // TODO
}

// qpackTable
type qpackTable struct {
	entries [1]qpackTableEntry // TODO: size
	content [_4K]byte
}

func (t *qpackTable) init() {
}

func (t *qpackTable) get() {
}
func (t *qpackTable) add() {
}

// http3Buffer
type http3Buffer struct {
	buf [_16K]byte // frame header + frame payload
	ref atomic.Int32
}

var poolHTTP3Buffer sync.Pool

func getHTTP3Buffer() *http3Buffer {
	var inBuffer *http3Buffer
	if x := poolHTTP3Buffer.Get(); x == nil {
		inBuffer = new(http3Buffer)
	} else {
		inBuffer = x.(*http3Buffer)
	}
	return inBuffer
}
func putHTTP3Buffer(inBuffer *http3Buffer) { poolHTTP3Buffer.Put(inBuffer) }

func (b *http3Buffer) size() uint32  { return uint32(cap(b.buf)) }
func (b *http3Buffer) getRef() int32 { return b.ref.Load() }
func (b *http3Buffer) incRef()       { b.ref.Add(1) }
func (b *http3Buffer) decRef() {
	if b.ref.Add(-1) == 0 {
		if DebugLevel() >= 1 {
			Printf("putHTTP3Buffer ref=%d\n", b.ref.Load())
		}
		putHTTP3Buffer(b)
	}
}

// http3InFrame is the HTTP/3 incoming frame.
type http3InFrame struct {
	// TODO
}

func (f *http3InFrame) zero() { *f = http3InFrame{} }

// http3OutFrame is the HTTP/3 outgoing frame.
type http3OutFrame struct {
	// TODO
}

func (f *http3OutFrame) zero() { *f = http3OutFrame{} }
