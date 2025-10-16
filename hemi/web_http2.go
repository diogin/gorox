// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// HTTP/2 implementation. See RFC 9113, RFC 7541, and RFC 8441.

// Server Push is not supported because it's rarely used. Chrome and Firefox even removed it.

package hemi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/diogin/gorox/hemi/library/system"
)

func init() {
	RegisterServer("httpxServer", func(compName string, stage *Stage) Server {
		s := new(httpxServer)
		s.onCreate(compName, stage)
		return s
	})
}

// httpxServer is the HTTP/1.x and HTTP/2 server. An httpxServer has many httpxGates.
type httpxServer struct {
	// Parent
	httpServer_[*httpxGate]
	// States
	httpMode int8 // 0: adaptive, 1: http/1.x, 2: http/2
}

func (s *httpxServer) onCreate(compName string, stage *Stage) {
	s.httpServer_.onCreate(compName, stage)

	s.httpMode = 1 // http/1.x by default. TODO(diogin): change to adaptive mode after http/2 server has been fully implemented
}

func (s *httpxServer) OnConfigure() {
	s.httpServer_.onConfigure()

	if DebugLevel() >= 2 { // TODO(diogin): remove this condition after http/2 server has been fully implemented
		// .httpMode
		var mode string
		s.ConfigureString("httpMode", &mode, func(value string) error {
			value = strings.ToLower(value)
			switch value {
			case "http1", "http/1", "http/1.x", "http2", "http/2", "adaptive":
				return nil
			default:
				return errors.New(".httpMode has an invalid value")
			}
		}, "adaptive")
		switch mode {
		case "http1", "http/1", "http/1.x":
			s.httpMode = 1
		case "http2", "http/2":
			s.httpMode = 2
		default:
			s.httpMode = 0
		}
	}
}
func (s *httpxServer) OnPrepare() {
	s.httpServer_.onPrepare()

	if s.TLSMode() {
		var nextProtos []string
		switch s.httpMode {
		case 2:
			nextProtos = []string{"h2"}
		case 1:
			nextProtos = []string{"http/1.1"}
		default: // adaptive mode
			nextProtos = []string{"h2", "http/1.1"}
		}
		s.tlsConfig.NextProtos = nextProtos
	}
}

func (s *httpxServer) Serve() { // runner
	for id := range s.numGates {
		gate := new(httpxGate)
		gate.onNew(s, id)
		if err := gate.Open(); err != nil {
			EnvExitln(err.Error())
		}
		s.AddGate(gate)
		go gate.Serve()
	}
	s.WaitGates()
	if DebugLevel() >= 2 {
		Printf("httpxServer=%s done\n", s.CompName())
	}
	s.stage.DecServer()
}

// httpxGate is a gate of httpxServer.
type httpxGate struct {
	// Parent
	httpGate_[*httpxServer]
	// States
	listener net.Listener // the real gate. set after open
}

func (g *httpxGate) onNew(server *httpxServer, id int32) {
	g.httpGate_.onNew(server, id)
}

func (g *httpxGate) Open() error {
	var (
		listener net.Listener
		err      error
	)
	if g.UDSMode() {
		address := g.Address()
		// UDS doesn't support SO_REUSEADDR or SO_REUSEPORT, so we have to remove it first.
		// This affects graceful upgrading, maybe we can implement fd transfer in the future.
		os.Remove(address)
		if listener, err = net.Listen("unix", address); err == nil {
			g.listener = listener.(*net.UnixListener)
			if DebugLevel() >= 1 {
				Printf("httpxGate id=%d address=%s opened!\n", g.id, g.Address())
			}
		}
	} else {
		listenConfig := new(net.ListenConfig)
		listenConfig.Control = func(network string, address string, rawConn syscall.RawConn) error {
			if err := system.SetReusePort(rawConn); err != nil {
				return err
			}
			return system.SetDeferAccept(rawConn)
		}
		if listener, err = listenConfig.Listen(context.Background(), "tcp", g.Address()); err == nil {
			g.listener = listener.(*net.TCPListener)
			if DebugLevel() >= 1 {
				Printf("httpxGate id=%d address=%s opened!\n", g.id, g.Address())
			}
		}
	}
	return err
}
func (g *httpxGate) Shut() error {
	g.MarkShut()
	return g.listener.Close() // breaks serveXXX()
}

func (g *httpxGate) Serve() { // runner
	if g.UDSMode() {
		g.serveUDS()
	} else if g.TLSMode() {
		g.serveTLS()
	} else {
		g.serveTCP()
	}
}
func (g *httpxGate) serveUDS() {
	listener := g.listener.(*net.UnixListener)
	connID := int64(1)
	for {
		udsConn, err := listener.AcceptUnix()
		if err != nil {
			if g.IsShut() {
				break
			} else {
				//g.stage.Logf("httpxServer[%s] httpxGate[%d]: accept error: %v\n", g.server.compName, g.id, err)
				continue
			}
		}
		g.IncConn()
		if concurrentConns := g.IncConcurrentConns(); g.ReachLimit(concurrentConns) {
			g.justClose(udsConn)
			continue
		}
		rawConn, err := udsConn.SyscallConn()
		if err != nil {
			g.justClose(udsConn)
			//g.stage.Logf("httpxServer[%s] httpxGate[%d]: SyscallConn() error: %v\n", g.server.compName, g.id, err)
			continue
		}
		if g.server.httpMode == 2 {
			servConn := getServer2Conn(connID, g, udsConn, rawConn)
			go servConn.manage() // servConn will be put to pool in manage()
		} else {
			servConn := getServer1Conn(connID, g, udsConn, rawConn)
			go servConn.serve() // servConn will be put to pool in serve()
		}
		connID++
	}
	g.WaitConns() // TODO: max timeout?
	if DebugLevel() >= 2 {
		Printf("httpxGate=%d TCP done\n", g.id)
	}
	g.server.DecGate()
}
func (g *httpxGate) serveTLS() {
	listener := g.listener.(*net.TCPListener)
	connID := int64(1)
	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			if g.IsShut() {
				break
			} else {
				//g.stage.Logf("httpxServer[%s] httpxGate[%d]: accept error: %v\n", g.server.compName, g.id, err)
				continue
			}
		}
		g.IncConn()
		if concurrentConns := g.IncConcurrentConns(); g.ReachLimit(concurrentConns) {
			g.justClose(tcpConn)
			continue
		}
		tlsConn := tls.Server(tcpConn, g.server.TLSConfig())
		// TODO: configure timeout
		if tlsConn.SetDeadline(time.Now().Add(10*time.Second)) != nil || tlsConn.Handshake() != nil {
			g.justClose(tlsConn)
			continue
		}
		if connState := tlsConn.ConnectionState(); connState.NegotiatedProtocol == "h2" {
			servConn := getServer2Conn(connID, g, tlsConn, nil)
			go servConn.manage() // servConn will be put to pool in manage()
		} else {
			servConn := getServer1Conn(connID, g, tlsConn, nil)
			go servConn.serve() // servConn will be put to pool in serve()
		}
		connID++
	}
	g.WaitConns() // TODO: max timeout?
	if DebugLevel() >= 2 {
		Printf("httpxGate=%d TLS done\n", g.id)
	}
	g.server.DecGate()
}
func (g *httpxGate) serveTCP() {
	listener := g.listener.(*net.TCPListener)
	connID := int64(1)
	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			if g.IsShut() {
				break
			} else {
				//g.stage.Logf("httpxServer[%s] httpxGate[%d]: accept error: %v\n", g.server.compName, g.id, err)
				continue
			}
		}
		g.IncConn()
		if concurrentConns := g.IncConcurrentConns(); g.ReachLimit(concurrentConns) {
			g.justClose(tcpConn)
			continue
		}
		rawConn, err := tcpConn.SyscallConn()
		if err != nil {
			g.justClose(tcpConn)
			//g.stage.Logf("httpxServer[%s] httpxGate[%d]: SyscallConn() error: %v\n", g.server.compName, g.id, err)
			continue
		}
		if g.server.httpMode == 2 {
			servConn := getServer2Conn(connID, g, tcpConn, rawConn)
			go servConn.manage() // servConn will be put to pool in manage()
		} else {
			servConn := getServer1Conn(connID, g, tcpConn, rawConn)
			go servConn.serve() // servConn will be put to pool in serve()
		}
		connID++
	}
	g.WaitConns() // TODO: max timeout?
	if DebugLevel() >= 2 {
		Printf("httpxGate=%d TCP done\n", g.id)
	}
	g.server.DecGate()
}

func (g *httpxGate) justClose(netConn net.Conn) {
	netConn.Close()
	g.DecConcurrentConns()
	g.DecConn()
}

// server2Conn is the server-side HTTP/2 connection.
type server2Conn struct {
	// Parent
	http2Conn_[*httpxGate, *server2Stream]
	// Mixins
	// Conn states (stocks)
	// Conn states (controlled)
	// Conn states (non-zeros)
	// Conn states (zeros)
}

var poolServer2Conn sync.Pool

func getServer2Conn(id int64, gate *httpxGate, netConn net.Conn, rawConn syscall.RawConn) *server2Conn {
	var servConn *server2Conn
	if x := poolServer2Conn.Get(); x == nil {
		servConn = new(server2Conn)
	} else {
		servConn = x.(*server2Conn)
	}
	servConn.onGet(id, gate, netConn, rawConn)
	return servConn
}
func putServer2Conn(servConn *server2Conn) {
	servConn.onPut()
	poolServer2Conn.Put(servConn)
}

func (c *server2Conn) onGet(id int64, gate *httpxGate, netConn net.Conn, rawConn syscall.RawConn) {
	c.http2Conn_.onGet(id, gate, netConn, rawConn)
}
func (c *server2Conn) onPut() {
	c.http2Conn_.onPut()
}

var server2PrefaceAndMore = []byte{
	// server preface settings
	0, 0, 30, // length=30
	4,          // kind=http2FrameSettings
	0,          // flags=
	0, 0, 0, 0, // streamID=0
	0, 1, 0x00, 0x00, 0x10, 0x00, // maxHeaderTableSize=4K
	0, 3, 0x00, 0x00, 0x00, 0x7f, // maxConcurrentStreams=127
	0, 4, 0x00, 0x00, 0xff, 0xff, // initialWindowSize=64K1
	0, 5, 0x00, 0x00, 0x40, 0x00, // maxFrameSize=16K
	0, 6, 0x00, 0x00, 0x40, 0x00, // maxHeaderListSize=16K

	// window update for the entire connection
	0, 0, 4, // length=4
	8,          // kind=http2FrameWindowUpdate
	0,          // flags=
	0, 0, 0, 0, // streamID=0
	0x7f, 0xff, 0x00, 0x00, // windowSize=2G1-64K1

	// ack client settings
	0, 0, 0, // length=0
	4,          // kind=http2FrameSettings
	1,          // flags=ack
	0, 0, 0, 0, // streamID=0
}

func (c *server2Conn) manage() { // runner
	Printf("========================== conn=%d start =========================\n", c.id)
	defer func() {
		Printf("========================== conn=%d exit =========================\n", c.id)
		putServer2Conn(c)
	}()
	go c.receive(true)
	if prism := <-c.incomingChan; prism != nil {
		c.closeConn()
		return
	}
	preface := <-c.incomingChan
	inFrame, ok := preface.(*http2InFrame)
	if !ok {
		c.closeConn()
		return
	}
	if inFrame.kind != http2FrameSettings || inFrame.ack {
		goto bad
	}
	if err := c._updatePeerSettings(inFrame, false); err != nil {
		goto bad
	}
	// Send server connection preface
	if err := c.setWriteDeadline(); err != nil {
		goto bad
	}
	if n, err := c.write(server2PrefaceAndMore); err == nil {
		Printf("--------------------- conn=%d CALL WRITE=%d -----------------------\n", c.id, n)
		Printf("conn=%d ---> %v\n", c.id, server2PrefaceAndMore)
		// Successfully handshake means we have acknowledged client settings and sent our settings. Still need to receive a settings ACK from client.
		goto serve
	} else {
		Printf("conn=%d error=%s\n", c.id, err.Error())
	}
bad:
	c.closeConn()
	c.waitReceive = true
	goto wait
serve:
	for { // each inFrame from c.receive() and outFrame from server streams
		select {
		case incoming := <-c.incomingChan: // got an incoming frame from c.receive()
			if inFrame, ok := incoming.(*http2InFrame); ok { // DATA, FIELDS, PRIORITY, RESET_STREAM, SETTINGS, PING, WINDOW_UPDATE, and unknown
				if inFrame.isUnknown() {
					// Implementations MUST ignore and discard frames of unknown types.
					continue
				}
				if err := server2InFrameProcessors[inFrame.kind](c, inFrame); err == nil {
					// Successfully processed. Next one.
					continue
				} else if h2e, ok := err.(http2Error); ok {
					c.goawayCloseConn(h2e)
				} else { // processor i/o error
					c.goawayCloseConn(http2ErrorInternal)
				}
				// c.manage() was broken, but c.receive() was not. need wait
				c.waitReceive = true
			} else { // got an error from c.receive(), it must be broken and quit.
				if h2e, ok := incoming.(http2Error); ok {
					c.goawayCloseConn(h2e)
				} else if netErr, ok := incoming.(net.Error); ok && netErr.Timeout() {
					c.goawayCloseConn(http2ErrorNoError)
				} else {
					c.closeConn()
				}
			}
			break serve
		case outFrame := <-c.outgoingChan: // got an outgoing frame from streams. MUST be fields frame or data frame!
			// TODO: collect as many outgoing frames as we can?
			Printf("%+v\n", outFrame)
			if outFrame.endStream { // a stream has ended
				c.retireStream(outFrame.stream)
				c.concurrentStreams--
			}
			if err := c.sendOutFrame(outFrame); err != nil {
				// send side is broken.
				c.closeConn()
				c.waitReceive = true
				break serve
			}
		}
	}
	Printf("conn=%d waiting for active streams to end\n", c.id)
	for c.concurrentStreams > 0 {
		outFrame := <-c.outgoingChan
		if outFrame.endStream {
			c.retireStream(outFrame.stream)
			c.concurrentStreams--
		}
	}
wait:
	if c.waitReceive {
		Printf("conn=%d waiting for c.receive() to quit\n", c.id)
		for {
			incoming := <-c.incomingChan
			if _, ok := incoming.(*http2InFrame); !ok { // an error from c.receive() means it's quit
				break
			}
		}
	}
	Printf("conn=%d c.manage() quit\n", c.id)
}

var server2InFrameProcessors = [http2NumFrameKinds]func(*server2Conn, *http2InFrame) error{
	(*server2Conn).processDataInFrame,
	(*server2Conn).processFieldsInFrame,
	(*server2Conn).processPriorityInFrame,
	(*server2Conn).processResetStreamInFrame,
	(*server2Conn).processSettingsInFrame,
	(*server2Conn).processPushPromiseInFrame,
	(*server2Conn).processPingInFrame,
	(*server2Conn).processGoawayInFrame,
	(*server2Conn).processWindowUpdateInFrame,
	(*server2Conn).processContinuationInFrame,
}

func (c *server2Conn) processFieldsInFrame(fieldsInFrame *http2InFrame) error {
	var (
		servStream *server2Stream
		servReq    *server2Request
	)
	streamID := fieldsInFrame.streamID
	if streamID > c.lastStreamID { // new stream
		if c.concurrentStreams == http2MaxConcurrentStreams {
			return http2ErrorProtocol
		}
		c.lastStreamID = streamID
		c.cumulativeStreams.Add(1)
		servStream = getServer2Stream(c, streamID, c.peerSettings.initialWindowSize)
		servReq = &servStream.request
		Println("xxxxxxxxxxx")
		if !c.decodeFields(fieldsInFrame.effective(), &servReq.input) {
			Println("yyyyyyyyyyy")
			putServer2Stream(servStream)
			return http2ErrorCompression
		}
		Println("zzzzzzzz")
		if fieldsInFrame.endStream {
			servStream.state = http2StateRemoteClosed
		} else {
			servStream.state = http2StateOpen
		}
		c.appendStream(servStream)
		c.concurrentStreams++
		go servStream.execute()
	} else { // old stream
		servStream := c.searchStream(streamID)
		if servStream == nil { // no specified active stream
			return http2ErrorProtocol
		}
		if servStream.state != http2StateOpen {
			return http2ErrorProtocol
		}
		if !fieldsInFrame.endStream { // here must be trailer fields that end the stream
			return http2ErrorProtocol
		}
		servReq = &servStream.request
		servReq.receiving = httpSectionTrailers
		if !c.decodeFields(fieldsInFrame.effective(), &servReq.array) { // TODO: determine from index in array
			return http2ErrorCompression
		}
	}
	return nil
}
func (c *server2Conn) processSettingsInFrame(settingsInFrame *http2InFrame) error {
	if settingsInFrame.ack {
		c.acknowledged = true
		return nil
	}
	// TODO: client sent a new settings
	return nil
}

func (c *server2Conn) goawayCloseConn(h2e http2Error) {
	goawayOutFrame := &c.outFrame
	goawayOutFrame.streamID = 0
	goawayOutFrame.length = 8
	goawayOutFrame.kind = http2FrameGoaway
	binary.BigEndian.PutUint32(goawayOutFrame.outBuffer[0:4], c.lastStreamID)
	binary.BigEndian.PutUint32(goawayOutFrame.outBuffer[4:8], uint32(h2e))
	goawayOutFrame.payload = goawayOutFrame.outBuffer[0:8]
	c.sendOutFrame(goawayOutFrame) // ignore error
	goawayOutFrame.zero()
	c.closeConn()
}

func (c *server2Conn) closeConn() {
	if DebugLevel() >= 2 {
		Printf("conn=%d closed by manage()\n", c.id)
	}
	c.netConn.Close()
	c.holder.DecConcurrentConns()
	c.holder.DecConn()
}

// server2Stream is the server-side HTTP/2 stream.
type server2Stream struct {
	// Parent
	http2Stream_[*server2Conn]
	// Mixins
	// Assocs
	request  server2Request  // the http/2 request.
	response server2Response // the http/2 response.
	socket   *server2Socket  // ...
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolServer2Stream sync.Pool

func getServer2Stream(conn *server2Conn, id uint32, remoteWindow int32) *server2Stream {
	var servStream *server2Stream
	if x := poolServer2Stream.Get(); x == nil {
		servStream = new(server2Stream)
		servReq, servResp := &servStream.request, &servStream.response
		servReq.stream = servStream
		servReq.in = servReq
		servResp.stream = servStream
		servResp.out = servResp
		servResp.request = servReq
	} else {
		servStream = x.(*server2Stream)
	}
	servStream.onUse(conn, id, remoteWindow)
	return servStream
}
func putServer2Stream(servStream *server2Stream) {
	servStream.onEnd()
	poolServer2Stream.Put(servStream)
}

func (s *server2Stream) onUse(conn *server2Conn, id uint32, remoteWindow int32) { // for non-zeros
	s.http2Stream_.onUse(conn, id)

	s.localWindow = _64K1         // max size of r.bodyWindow
	s.remoteWindow = remoteWindow // may be changed by the peer
	s.request.onUse()
	s.response.onUse()
}
func (s *server2Stream) onEnd() { // for zeros
	s.response.onEnd()
	s.request.onEnd()
	if s.socket != nil {
		s.socket.onEnd()
		s.socket = nil
	}

	s.http2Stream_.onEnd()
}

func (s *server2Stream) execute() { // runner
	defer putServer2Stream(s)
	// TODO ...
	if DebugLevel() >= 2 {
		Println("stream processing...")
	}
}
func (s *server2Stream) _serveAbnormal(req *server2Request, resp *server2Response) { // 4xx & 5xx
	// TODO
	// s.setWriteDeadline() // for _serveAbnormal
	// s.writeVec()
}
func (s *server2Stream) _writeContinue() bool { // 100 continue
	// TODO
	// s.setWriteDeadline() // for _writeContinue
	// s.write()
	return false
}

func (s *server2Stream) executeExchan(webapp *Webapp, req *server2Request, resp *server2Response) { // request & response
	// TODO
	webapp.dispatchExchan(req, resp)
}
func (s *server2Stream) executeSocket() { // see RFC 8441: https://datatracker.ietf.org/doc/html/rfc8441
	// TODO
}

// server2Request is the server-side HTTP/2 request.
type server2Request struct { // incoming. needs parsing
	// Parent
	serverRequest_
	// Assocs
	in2 _http2In_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *server2Request) onUse() {
	r.serverRequest_.onUse(Version2)
	r.in2.onUse(&r._httpIn_)
}
func (r *server2Request) onEnd() {
	r.serverRequest_.onEnd()
	r.in2.onEnd()
}

func (r *server2Request) joinHeaders(p []byte) bool {
	if len(p) > 0 {
		if !r.in2._growHeaders(int32(len(p))) {
			return false
		}
		r.inputEdge += int32(copy(r.input[r.inputEdge:], p))
	}
	return true
}
func (r *server2Request) readContent() (data []byte, err error) { return r.in2.readContent() }
func (r *server2Request) joinTrailers(p []byte) bool {
	// TODO: to r.array
	return false
}

// server2Response is the server-side HTTP/2 response.
type server2Response struct { // outgoing. needs building
	// Parent
	serverResponse_
	// Assocs
	out2 _http2Out_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *server2Response) onUse() {
	r.serverResponse_.onUse(Version2)
	r.out2.onUse(&r._httpOut_)
}
func (r *server2Response) onEnd() {
	r.serverResponse_.onEnd()
	r.out2.onEnd()
}

func (r *server2Response) addHeader(name []byte, value []byte) bool {
	return r.out2.addHeader(name, value)
}
func (r *server2Response) header(name []byte) (value []byte, ok bool) { return r.out2.header(name) }
func (r *server2Response) hasHeader(name []byte) bool                 { return r.out2.hasHeader(name) }
func (r *server2Response) delHeader(name []byte) (deleted bool)       { return r.out2.delHeader(name) }
func (r *server2Response) delHeaderAt(i uint8)                        { r.out2.delHeaderAt(i) }

func (r *server2Response) AddHTTPSRedirection(authority string) bool {
	// TODO
	return false
}
func (r *server2Response) AddHostnameRedirection(hostname string) bool {
	// TODO
	return false
}
func (r *server2Response) AddDirectoryRedirection() bool {
	// TODO
	return false
}

func (r *server2Response) AddCookie(cookie *Cookie) bool {
	// TODO
	return false
}

func (r *server2Response) sendChain() error { return r.out2.sendChain() }

func (r *server2Response) echoHeaders() error { return r.out2.writeHeaders() }
func (r *server2Response) echoChain() error   { return r.out2.echoChain() }

func (r *server2Response) addTrailer(name []byte, value []byte) bool {
	return r.out2.addTrailer(name, value)
}
func (r *server2Response) trailer(name []byte) (value []byte, ok bool) { return r.out2.trailer(name) }

func (r *server2Response) proxyPass1xx(backResp BackendResponse) bool {
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
func (r *server2Response) proxyPassHeaders() error          { return r.out2.writeHeaders() }
func (r *server2Response) proxyPassBytes(data []byte) error { return r.out2.proxyPassBytes(data) }

func (r *server2Response) finalizeHeaders() { // add at most 256 bytes
	// TODO
	/*
		// date: Sun, 06 Nov 1994 08:49:37 GMT
		if r.iDate == 0 {
			clock := r.stream.(*server2Stream).conn.gate.stage.clock
			r.outputEdge += uint16(clock.writeDate2(r.output[r.outputEdge:]))
		}
	*/
}
func (r *server2Response) finalizeVague() error {
	// TODO
	return nil
}

func (r *server2Response) addedHeaders() []byte { return nil } // TODO
func (r *server2Response) fixedHeaders() []byte { return nil } // TODO

// server2Socket is the server-side HTTP/2 webSocket.
type server2Socket struct { // incoming and outgoing
	// Parent
	serverSocket_
	// Assocs
	so2 _http2Socket_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolServer2Socket sync.Pool

func getServer2Socket(stream *server2Stream) *server2Socket {
	// TODO
	return nil
}
func putServer2Socket(socket *server2Socket) {
	// TODO
}

func (s *server2Socket) onUse() {
	s.serverSocket_.onUse()
	s.so2.onUse(&s._httpSocket_)
}
func (s *server2Socket) onEnd() {
	s.serverSocket_.onEnd()
	s.so2.onEnd()
}

func (s *server2Socket) serverTodo2() {
	s.serverTodo()
	s.so2.todo2()
}

////////////////////////////////////////////////////////////////

func init() {
	RegisterBackend("http2Backend", func(compName string, stage *Stage) Backend {
		b := new(HTTP2Backend)
		b.OnCreate(compName, stage)
		return b
	})
}

// HTTP2Backend
type HTTP2Backend struct {
	// Parent
	httpBackend_[*http2Node]
	// States
}

func (b *HTTP2Backend) CreateNode(compName string) Node {
	node := new(http2Node)
	node.onCreate(compName, b.stage, b)
	b.AddNode(node)
	return node
}

func (b *HTTP2Backend) AcquireStream(servReq ServerRequest) (BackendStream, error) {
	return b.nodes[b.nodeIndexGet()].fetchStream()
}
func (b *HTTP2Backend) ReleaseStream(backStream BackendStream) {
	backStream2 := backStream.(*backend2Stream)
	backStream2.conn.holder.storeStream(backStream2)
}

// http2Node
type http2Node struct {
	// Parent
	httpNode_[*HTTP2Backend, *backend2Conn]
	// States
}

func (n *http2Node) onCreate(compName string, stage *Stage, backend *HTTP2Backend) {
	n.httpNode_.onCreate(compName, stage, backend)
}

func (n *http2Node) OnConfigure() {
	n.httpNode_.onConfigure()
	if n.tlsMode {
		n.tlsConfig.InsecureSkipVerify = true
		n.tlsConfig.NextProtos = []string{"h2"}
	}
}
func (n *http2Node) OnPrepare() {
	n.httpNode_.onPrepare()
}

func (n *http2Node) Maintain() { // runner
	n.LoopRun(time.Second, func(now time.Time) {
		// TODO: health check, markDown, markUp()
	})
	// TODO: wait for all conns
	if DebugLevel() >= 2 {
		Printf("http2Node=%s done\n", n.compName)
	}
	n.backend.DecNode()
}

func (n *http2Node) fetchStream() (*backend2Stream, error) {
	// Note: A backend2Conn can be used concurrently, limited by maxConcurrentStreams.
	// TODO
	return nil, nil
}
func (n *http2Node) _dialUDS() (*backend2Conn, error) {
	// TODO
	return nil, nil
}
func (n *http2Node) _dialTLS() (*backend2Conn, error) {
	// TODO
	return nil, nil
}
func (n *http2Node) _dialTCP() (*backend2Conn, error) {
	// TODO
	return nil, nil
}
func (n *http2Node) storeStream(backStream *backend2Stream) {
	// Note: A backend2Conn can be used concurrently, limited by maxConcurrentStreams.
	// TODO
}

// backend2Conn is the backend-side HTTP/2 connection.
type backend2Conn struct {
	// Parent
	http2Conn_[*http2Node, *backend2Stream]
	// Mixins
	// Assocs
	// Conn states (stocks)
	// Conn states (controlled)
	expireTime time.Time // when the conn is considered expired
	// Conn states (non-zeros)
	// Conn states (zeros)
}

var poolBackend2Conn sync.Pool

func getBackend2Conn(id int64, node *http2Node, netConn net.Conn, rawConn syscall.RawConn) *backend2Conn {
	var backConn *backend2Conn
	if x := poolBackend2Conn.Get(); x == nil {
		backConn = new(backend2Conn)
	} else {
		backConn = x.(*backend2Conn)
	}
	backConn.onGet(id, node, netConn, rawConn)
	return backConn
}
func putBackend2Conn(backConn *backend2Conn) {
	backConn.onPut()
	poolBackend2Conn.Put(backConn)
}

func (c *backend2Conn) onGet(id int64, node *http2Node, netConn net.Conn, rawConn syscall.RawConn) {
	c.http2Conn_.onGet(id, node, netConn, rawConn)
}
func (c *backend2Conn) onPut() {
	c.expireTime = time.Time{}
	c.http2Conn_.onPut()
}

func (c *backend2Conn) isAlive() bool {
	return c.expireTime.IsZero() || time.Now().Before(c.expireTime)
}

func (c *backend2Conn) newStream() (*backend2Stream, error) { // used by http2Node
	// Note: A backend2Conn can be used concurrently, limited by maxConcurrentStreams.
	// TODO: incRef, backStream.onUse()
	return nil, nil
}
func (c *backend2Conn) delStream(backStream *backend2Stream) { // used by http2Node
	// Note: A backend2Conn can be used concurrently, limited by maxConcurrentStreams.
	// TODO
	//backStream.onEnd()
}

var backend2PrefaceAndMore = []byte{
	// prism
	'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0', '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',

	// client preface settings
	0, 0, 36, // length=36
	4,          // kind=http2FrameSettings
	0,          // flags=
	0, 0, 0, 0, // streamID=0
	0, 1, 0x00, 0x00, 0x10, 0x00, // maxHeaderTableSize=4K
	0, 2, 0x00, 0x00, 0x00, 0x00, // enablePush=0
	0, 3, 0x00, 0x00, 0x00, 0x7f, // maxConcurrentStreams=127
	0, 4, 0x00, 0x00, 0xff, 0xff, // initialWindowSize=64K1
	0, 5, 0x00, 0x00, 0x40, 0x00, // maxFrameSize=16K
	0, 6, 0x00, 0x00, 0x40, 0x00, // maxHeaderListSize=16K

	// window update for the entire connection
	0, 0, 4, // length=4
	8,          // kind=http2FrameWindowUpdate
	0,          // flags=
	0, 0, 0, 0, // streamID=0
	0x7f, 0xff, 0x00, 0x00, // windowSize=2G1-64K1
}

func (c *backend2Conn) manage() { // runner
	// setWriteDeadline()
	// write client preface

	// go c.receive(false)

	// read server preface
	// c._updatePeerSettings(true)

	// setWriteDeadline()
	// ack server preface
}

var backend2InFrameProcessors = [http2NumFrameKinds]func(*backend2Conn, *http2InFrame) error{
	(*backend2Conn).processDataInFrame,
	(*backend2Conn).processFieldsInFrame,
	(*backend2Conn).processPriorityInFrame,
	(*backend2Conn).processResetStreamInFrame,
	(*backend2Conn).processSettingsInFrame,
	(*backend2Conn).processPushPromiseInFrame,
	(*backend2Conn).processPingInFrame,
	(*backend2Conn).processGoawayInFrame,
	(*backend2Conn).processWindowUpdateInFrame,
	(*backend2Conn).processContinuationInFrame,
}

func (c *backend2Conn) processFieldsInFrame(fieldsInFrame *http2InFrame) error {
	// TODO
	return nil
}
func (c *backend2Conn) processSettingsInFrame(settingsInFrame *http2InFrame) error {
	// TODO: server sent a new settings
	return nil
}

func (c *backend2Conn) Close() error {
	netConn := c.netConn
	putBackend2Conn(c)
	return netConn.Close()
}

// backend2Stream is the backend-side HTTP/2 stream.
type backend2Stream struct {
	// Parent
	http2Stream_[*backend2Conn]
	// Mixins
	// Assocs
	response backend2Response // the backend-side http/2 response
	request  backend2Request  // the backend-side http/2 request
	socket   *backend2Socket  // the backend-side http/2 webSocket
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolBackend2Stream sync.Pool

func getBackend2Stream(conn *backend2Conn, id uint32, remoteWindow int32) *backend2Stream {
	var backStream *backend2Stream
	if x := poolBackend2Stream.Get(); x == nil {
		backStream = new(backend2Stream)
		backResp, backReq := &backStream.response, &backStream.request
		backResp.stream = backStream
		backResp.in = backResp
		backReq.stream = backStream
		backReq.out = backReq
		backReq.response = backResp
	} else {
		backStream = x.(*backend2Stream)
	}
	backStream.onUse(conn, id, remoteWindow)
	return backStream
}
func putBackend2Stream(backStream *backend2Stream) {
	backStream.onEnd()
	poolBackend2Stream.Put(backStream)
}

func (s *backend2Stream) onUse(conn *backend2Conn, id uint32, remoteWindow int32) { // for non-zeros
	s.http2Stream_.onUse(conn, id)

	s.localWindow = _64K1         // max size of r.bodyWindow
	s.remoteWindow = remoteWindow // may be changed by the peer
	s.response.onUse()
	s.request.onUse()
}
func (s *backend2Stream) onEnd() { // for zeros
	s.request.onEnd()
	s.response.onEnd()
	if s.socket != nil {
		s.socket.onEnd()
		s.socket = nil
	}

	s.http2Stream_.onEnd()
}

func (s *backend2Stream) Response() BackendResponse { return &s.response }
func (s *backend2Stream) Request() BackendRequest   { return &s.request }
func (s *backend2Stream) Socket() BackendSocket     { return nil } // TODO. See RFC 8441: https://datatracker.ietf.org/doc/html/rfc8441

// backend2Response is the backend-side HTTP/2 response.
type backend2Response struct { // incoming. needs parsing
	// Parent
	backendResponse_
	// Assocs
	in2 _http2In_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *backend2Response) onUse() {
	r.backendResponse_.onUse(Version2)
	r.in2.onUse(&r._httpIn_)
}
func (r *backend2Response) onEnd() {
	r.backendResponse_.onEnd()
	r.in2.onEnd()
}

func (r *backend2Response) recvHead() { // control data + header section
	// TODO
}

func (r *backend2Response) readContent() (data []byte, err error) { return r.in2.readContent() }

// backend2Request is the backend-side HTTP/2 request.
type backend2Request struct { // outgoing. needs building
	// Parent
	backendRequest_
	// Assocs
	out2 _http2Out_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *backend2Request) onUse() {
	r.backendRequest_.onUse(Version2)
	r.out2.onUse(&r._httpOut_)
}
func (r *backend2Request) onEnd() {
	r.backendRequest_.onEnd()
	r.out2.onEnd()
}

func (r *backend2Request) addHeader(name []byte, value []byte) bool {
	return r.out2.addHeader(name, value)
}
func (r *backend2Request) header(name []byte) (value []byte, ok bool) { return r.out2.header(name) }
func (r *backend2Request) hasHeader(name []byte) bool                 { return r.out2.hasHeader(name) }
func (r *backend2Request) delHeader(name []byte) (deleted bool)       { return r.out2.delHeader(name) }
func (r *backend2Request) delHeaderAt(i uint8)                        { r.out2.delHeaderAt(i) }

func (r *backend2Request) AddCookie(name string, value string) bool {
	// TODO. need some space to place the cookie
	return false
}
func (r *backend2Request) proxyCopyCookies(servReq ServerRequest) bool { // NOTE: DO NOT merge into one "cookie" header field!
	// TODO: one by one?
	return true
}

func (r *backend2Request) sendChain() error { return r.out2.sendChain() }

func (r *backend2Request) echoHeaders() error { return r.out2.writeHeaders() }
func (r *backend2Request) echoChain() error   { return r.out2.echoChain() }

func (r *backend2Request) addTrailer(name []byte, value []byte) bool {
	return r.out2.addTrailer(name, value)
}
func (r *backend2Request) trailer(name []byte) (value []byte, ok bool) { return r.out2.trailer(name) }

func (r *backend2Request) proxySetMethodURI(method []byte, uri []byte, hasContent bool) bool { // :method = method, :path = uri
	// TODO: set :method and :path
	return false
}
func (r *backend2Request) proxySetAuthority(hostname []byte, colonport []byte) bool {
	// TODO: set :authority
	return false
}

func (r *backend2Request) proxyPassHeaders() error          { return r.out2.writeHeaders() }
func (r *backend2Request) proxyPassBytes(data []byte) error { return r.out2.proxyPassBytes(data) }

func (r *backend2Request) finalizeHeaders() { // add at most 256 bytes
	// TODO
}
func (r *backend2Request) finalizeVague() error {
	// TODO
	return nil
}

func (r *backend2Request) addedHeaders() []byte { return nil } // TODO
func (r *backend2Request) fixedHeaders() []byte { return nil } // TODO

// backend2Socket is the backend-side HTTP/2 webSocket.
type backend2Socket struct { // incoming and outgoing
	// Parent
	backendSocket_
	// Assocs
	so2 _http2Socket_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolBackend2Socket sync.Pool

func getBackend2Socket(stream *backend2Stream) *backend2Socket {
	// TODO
	return nil
}
func putBackend2Socket(socket *backend2Socket) {
	// TODO
}

func (s *backend2Socket) onUse() {
	s.backendSocket_.onUse()
	s.so2.onUse(&s._httpSocket_)
}
func (s *backend2Socket) onEnd() {
	s.backendSocket_.onEnd()
	s.so2.onEnd()
}

func (s *backend2Socket) backendTodo2() {
	s.backendTodo()
	s.so2.todo2()
}

////////////////////////////////////////////////////////////////

// http2Conn
type http2Conn interface { // for *backend2Conn and *server2Conn
	// Imports
	httpConn
	// Methods
}

// http2Conn_ is a parent.
type http2Conn_[H httpHolder, S http2Stream] struct { // for backend2Conn and server2Conn
	// Parent
	httpConn_[H]
	// Conn states (stocks)
	// Conn states (controlled)
	outFrame http2OutFrame[S] // used by c.manage() itself to send special out frames. immediately reset after use
	// Conn states (non-zeros)
	netConn      net.Conn                         // *net.TCPConn, *tls.Conn, *net.UnixConn
	rawConn      syscall.RawConn                  // for syscall. only usable when netConn is TCP/UDS
	peerSettings http2Settings                    // settings of the remote peer
	freeSlots    [http2MaxConcurrentStreams]uint8 // a stack holding free slots for streams of this connection in c.activeStreams and c.activeStreamIDs
	freeSlotsTop uint8                            // the stack top of c.freeSlots
	inBuffer     *http2Buffer                     // http2Buffer in use, for receiving incoming frames. may be replaced again and again during connection's lifetime
	decodeTable  hpackTable                       // <= 5 KiB. hpack table used for decoding field blocks that are received from remote
	incomingChan chan any                         // frames and errors generated by c.receive() and waiting for c.manage() to consume
	localWindow  int32                            // connection-level window (buffer) size for receiving incoming DATA frames
	remoteWindow int32                            // connection-level window (buffer) size for sending outgoing DATA frames
	outgoingChan chan *http2OutFrame[S]           // frames generated by streams of this connection and waiting for c.manage() to send
	encodeTable  hpackTable                       // <= 5 KiB. hpack table used for encoding field lists that are sent to remote
	// Conn states (zeros)
	lastWrite        time.Time                    // deadline of last write operation
	lastRead         time.Time                    // deadline of last read operation
	activeStreams    [http2MaxConcurrentStreams]S // <= 1 KiB. active (http2StateOpen, http2StateLocalClosed, http2StateRemoteClosed) streams
	lastSettingsTime time.Time                    // last settings time
	lastPingTime     time.Time                    // last ping time
	inFrame0         http2InFrame                 // incoming frame 0
	inFrame1         http2InFrame                 // incoming frame 1
	inFrame          *http2InFrame                // current incoming frame. refers to inFrame0 or inFrame1 in turn
	vector           net.Buffers                  // used by writeVec in c.manage()
	fixedVector      [64][]byte                   // 1.5 KiB. used by writeVec in c.manage()
	_http2Conn0                                   // all values in this struct must be zero by default!
}
type _http2Conn0 struct { // for fast reset, entirely
	activeStreamIDs    [http2MaxConcurrentStreams + 1]uint32 // ids of c.activeStreams. the extra 1 id is used for fast linear searching
	readDeadlines      [http2MaxConcurrentStreams + 1]int64  // 1 KiB
	writeDeadlines     [http2MaxConcurrentStreams + 1]int64  // 1 KiB
	_                  uint32
	lastStreamID       uint32 // id of last stream sent to backend or received by server
	cumulativeInFrames int64  // num of incoming frames
	concurrentStreams  uint8  // num of active streams
	acknowledged       bool   // server settings acknowledged by client?
	pingSent           bool   // is there a ping frame sent and waiting for response?
	waitReceive        bool   // ...
	//unackedSettings?
	//queuedControlFrames?
	inBufferEdge uint16 // incoming data ends at c.inBuffer.buf[c.inBufferEdge]
	sectBack     uint16 // incoming frame section (header or payload) begins from c.inBuffer.buf[c.sectBack]
	sectFore     uint16 // incoming frame section (header or payload) ends at c.inBuffer.buf[c.sectFore]
	contBack     uint16 // incoming continuation part (header or payload) begins from c.inBuffer.buf[c.contBack]
	contFore     uint16 // incoming continuation part (header or payload) ends at c.inBuffer.buf[c.contFore]
}

func (c *http2Conn_[H, S]) onGet(id int64, holder H, netConn net.Conn, rawConn syscall.RawConn) {
	c.httpConn_.onGet(id, holder)

	c.netConn = netConn
	c.rawConn = rawConn
	c.peerSettings = http2InitialSettings
	c.freeSlots = http2FreeSlots
	c.freeSlotsTop = 255 // +1 becomes 0
	if c.inBuffer == nil {
		c.inBuffer = getHTTP2Buffer()
		c.inBuffer.incRef()
	}
	c.decodeTable.init()
	if c.incomingChan == nil {
		c.incomingChan = make(chan any)
	}
	c.localWindow = _2G1 - _64K1                      // as a receiver, we disable connection-level flow control
	c.remoteWindow = c.peerSettings.initialWindowSize // after we received the peer's preface, this value will be changed to the real value.
	if c.outgoingChan == nil {
		c.outgoingChan = make(chan *http2OutFrame[S])
	}
	c.encodeTable.init()
}
func (c *http2Conn_[H, S]) onPut() {
	c.netConn = nil
	c.rawConn = nil
	// c.inBuffer is reserved
	// c.decodeTable is reserved
	// c.incomingChan is reserved
	// c.outgoingChan is reserved
	// c.encodeTable is reserved
	c.lastWrite = time.Time{}
	c.lastRead = time.Time{}
	c.activeStreams = [http2MaxConcurrentStreams]S{}
	c.lastSettingsTime = time.Time{}
	c.lastPingTime = time.Time{}
	c.inFrame0.zero()
	c.inFrame1.zero()
	c.inFrame = nil
	c.vector = nil
	c.fixedVector = [64][]byte{}
	c._http2Conn0 = _http2Conn0{}

	c.httpConn_.onPut()
}

func (c *http2Conn_[H, S]) receive(asServer bool) { // runner, employed by c.manage()
	if DebugLevel() >= 1 {
		defer Printf("conn=%d c.receive() quit\n", c.id)
	}
	if asServer { // We must read the HTTP/2 PRISM at the very begining
		if err := c.setReadDeadline(); err != nil {
			c.incomingChan <- err
			return
		}
		if err := c._growInFrame(24); err != nil { // HTTP/2 PRISM is exactly 24 bytes
			c.incomingChan <- err
			return
		}
		if !bytes.Equal(c.inBuffer.buf[:24], backend2PrefaceAndMore[:24]) {
			c.incomingChan <- http2ErrorProtocol
			return
		}
		c.incomingChan <- nil // notify c.manage() that we have successfully read the HTTP/2 PRISM
	}
	for { // each incoming frame
		inFrame, err := c.recvInFrame()
		if err != nil {
			c.incomingChan <- err
			return
		}
		if inFrame.kind == http2FrameGoaway {
			c.incomingChan <- http2ErrorNoError
			return
		}
		c.incomingChan <- inFrame
	}
}

func (c *http2Conn_[H, S]) _getFreeSlot() uint8 {
	c.freeSlotsTop++
	return c.freeSlots[c.freeSlotsTop]
}
func (c *http2Conn_[H, S]) _putFreeSlot(slot uint8) {
	c.freeSlots[c.freeSlotsTop] = slot
	c.freeSlotsTop--
}

func (c *http2Conn_[H, S]) appendStream(stream S) { // O(1)
	slot := c._getFreeSlot()
	stream.setSlot(slot)
	c.activeStreams[slot] = stream
	c.activeStreamIDs[slot] = stream.nativeID()
	if DebugLevel() >= 2 {
		Printf("conn=%d appendStream=%d at %d\n", c.id, stream.nativeID(), slot)
	}
}
func (c *http2Conn_[H, S]) searchStream(streamID uint32) S { // O(http2MaxConcurrentStreams), but in practice this linear search algorithm should be fast enough
	c.activeStreamIDs[http2MaxConcurrentStreams] = streamID // the stream id to search for
	slot := uint8(0)
	for c.activeStreamIDs[slot] != streamID {
		slot++
	}
	if slot != http2MaxConcurrentStreams { // found
		if DebugLevel() >= 2 {
			Printf("conn=%d searchStream=%d at %d\n", c.id, streamID, slot)
		}
		return c.activeStreams[slot]
	} else { // not found
		var null S // nil
		return null
	}
}
func (c *http2Conn_[H, S]) retireStream(stream S) { // O(1)
	slot := stream.getSlot()
	if DebugLevel() >= 2 {
		Printf("conn=%d retireStream=%d at %d\n", c.id, stream.nativeID(), slot)
	}
	var null S // nil
	c.activeStreams[slot] = null
	c.activeStreamIDs[slot] = 0
	c._putFreeSlot(slot)
}

func (c *http2Conn_[H, S]) recvInFrame() (*http2InFrame, error) { // excluding pushPromise, which is not supported, and continuation, which cannot arrive alone
	// Receive frame header
	c.sectBack = c.sectFore
	if err := c.setReadDeadline(); err != nil {
		return nil, err
	}
	if err := c._growInFrame(9); err != nil {
		return nil, err
	}
	// Decode frame header
	if c.inFrame == nil || c.inFrame == &c.inFrame1 {
		c.inFrame = &c.inFrame0
	} else {
		c.inFrame = &c.inFrame1
	}
	inFrame := c.inFrame
	if err := inFrame.decodeHeader(c.inBuffer.buf[c.sectBack:c.sectFore]); err != nil {
		return nil, err
	}
	// Receive frame payload
	c.sectBack = c.sectFore
	if err := c._growInFrame(inFrame.length); err != nil {
		return nil, err
	}
	// Mark frame payload
	inFrame.inBuffer = c.inBuffer
	inFrame.efctFrom = c.sectBack
	inFrame.efctEdge = c.sectFore
	if !inFrame.isUnknown() {
		// Check the frame
		if err := http2InFrameCheckers[inFrame.kind](inFrame); err != nil {
			return nil, err
		}
	}
	c.cumulativeInFrames++
	if c.cumulativeInFrames == 10 && !c.acknowledged { // TODO: change this policy?
		return nil, http2ErrorSettingsTimeout
	}
	if inFrame.kind == http2FrameFields && !inFrame.endFields { // continuations follow, coalesce them into fields frame
		if err := c._coalesceContinuations(inFrame); err != nil {
			return nil, err
		}
	}
	if DebugLevel() >= 2 {
		Printf("conn=%d <--- %+v\n", c.id, inFrame)
	}
	return inFrame, nil
}
func (c *http2Conn_[H, S]) _growInFrame(size uint16) error {
	c.sectFore += size // size is limited, so won't overflow
	if c.sectFore <= c.inBufferEdge {
		return nil
	}
	// c.sectFore > c.inBufferEdge, needs grow.
	if c.sectFore > c.inBuffer.size() { // needs slide
		if c.inBuffer.getRef() == 1 { // no streams are referring to c.inBuffer, so just slide
			c.inBufferEdge = uint16(copy(c.inBuffer.buf[:], c.inBuffer.buf[c.sectBack:c.inBufferEdge]))
		} else { // there are remaining streams referring to c.inBuffer. use a new inBuffer
			oldBuffer := c.inBuffer
			c.inBuffer = getHTTP2Buffer()
			c.inBuffer.incRef()
			c.inBufferEdge = uint16(copy(c.inBuffer.buf[:], oldBuffer.buf[c.sectBack:c.inBufferEdge]))
			oldBuffer.decRef()
		}
		c.sectFore -= c.sectBack
		c.sectBack = 0
	}
	return c._fillInBuffer(c.sectFore - c.inBufferEdge)
}
func (c *http2Conn_[H, S]) _fillInBuffer(size uint16) error {
	n, err := c.readAtLeast(c.inBuffer.buf[c.inBufferEdge:], int(size))
	if DebugLevel() >= 2 {
		Printf("--------------------- conn=%d CALL READ=%d -----------------------\n", c.id, n)
	}
	if err != nil && DebugLevel() >= 2 {
		Printf("conn=%d error=%s\n", c.id, err.Error())
	}
	c.inBufferEdge += uint16(n)
	return err
}

func (c *http2Conn_[H, S]) _coalesceContinuations(fieldsInFrame *http2InFrame) error { // into a single fields frame
	fieldsInFrame.inBuffer = nil // unset temporarily, will be restored at the end of continuations
	var continuationInFrame http2InFrame
	c.contBack, c.contFore = c.sectFore, c.sectFore
	for i := 0; i < 4; i++ { // max 4 continuation frames are allowed!
		// Receive continuation header
		if err := c._growContinuationFrame(9, fieldsInFrame); err != nil {
			return err
		}
		// Decode continuation header
		if err := continuationInFrame.decodeHeader(c.inBuffer.buf[c.contBack:c.contFore]); err != nil {
			return err
		}
		// Check continuation header
		if continuationInFrame.length == 0 || fieldsInFrame.length+continuationInFrame.length > http2MaxFrameSize {
			return http2ErrorFrameSize
		}
		if continuationInFrame.streamID != fieldsInFrame.streamID || continuationInFrame.kind != http2FrameContinuation {
			return http2ErrorProtocol
		}
		// Receive continuation payload
		c.contBack = c.contFore
		if err := c._growContinuationFrame(continuationInFrame.length, fieldsInFrame); err != nil {
			return err
		}
		// Append continuation frame to fields frame
		copy(c.inBuffer.buf[fieldsInFrame.efctEdge:], c.inBuffer.buf[c.contBack:c.contFore]) // may overwrite padding if exists
		fieldsInFrame.efctEdge += continuationInFrame.length
		fieldsInFrame.length += continuationInFrame.length // we don't care if padding is overwritten. just accumulate
		c.sectFore += continuationInFrame.length           // also accumulate fields payload, with padding included
		// End of fields frame?
		if continuationInFrame.endFields {
			fieldsInFrame.endFields = true
			fieldsInFrame.inBuffer = c.inBuffer // restore the inBuffer
			c.sectFore = c.contFore             // for next frame.
			return nil
		}
		c.contBack = c.contFore
	}
	return http2ErrorEnhanceYourCalm
}
func (c *http2Conn_[H, S]) _growContinuationFrame(size uint16, fieldsInFrame *http2InFrame) error {
	c.contFore += size                // won't overflow
	if c.contFore <= c.inBufferEdge { // inBuffer is sufficient
		return nil
	}
	// Needs grow. Cases are (A is payload of the fields frame):
	// c.inBuffer: [| .. ] | A | 9 | B | 9 | C | 9 | D |
	// c.inBuffer: [| .. ] | AB | oooo | 9 | C | 9 | D |
	// c.inBuffer: [| .. ] | ABC | ooooooooooo | 9 | D |
	// c.inBuffer: [| .. ] | ABCD | oooooooooooooooooo |
	if c.contFore > c.inBuffer.size() { // needs slide
		if c.sectBack == 0 { // cannot slide again
			// This should only happens when looking for frame header, the 9 bytes
			return http2ErrorFrameSize
		}
		// Now slide. Skip holes (if any) when sliding
		inBuffer := c.inBuffer
		if c.inBuffer.getRef() != 1 { // there are still streams referring to c.inBuffer. use a new inBuffer
			c.inBuffer = getHTTP2Buffer()
			c.inBuffer.incRef()
		}
		c.sectFore = uint16(copy(c.inBuffer.buf[:], inBuffer.buf[c.sectBack:c.sectFore]))
		c.inBufferEdge = c.sectFore + uint16(copy(c.inBuffer.buf[c.sectFore:], inBuffer.buf[c.contBack:c.inBufferEdge]))
		if inBuffer != c.inBuffer {
			inBuffer.decRef()
		}
		fieldsInFrame.efctFrom -= c.sectBack
		fieldsInFrame.efctEdge -= c.sectBack
		c.sectBack = 0
		c.contBack = c.sectFore
		c.contFore = c.contBack + size
	}
	return c._fillInBuffer(c.contFore - c.inBufferEdge)
}

func (c *http2Conn_[H, S]) processDataInFrame(dataInFrame *http2InFrame) error {
	// TODO
	return nil
}
func (c *http2Conn_[H, S]) processPriorityInFrame(priorityInFrame *http2InFrame) error { return nil } // do nothing, priority frames are ignored
func (c *http2Conn_[H, S]) processResetStreamInFrame(resetStreamInFrame *http2InFrame) error {
	streamID := resetStreamInFrame.streamID
	if streamID > c.lastStreamID {
		// RST_STREAM frames MUST NOT be sent for a stream in the "idle" state. If a RST_STREAM frame identifying an idle stream is received,
		// the recipient MUST treat this as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
		return http2ErrorProtocol
	}
	// TODO
	return nil
}
func (c *http2Conn_[H, S]) processPushPromiseInFrame(pushPromiseInFrame *http2InFrame) error {
	panic("pushPromise frames should be rejected priorly")
}
func (c *http2Conn_[H, S]) processPingInFrame(pingInFrame *http2InFrame) error {
	if pingInFrame.ack { // pong
		if !c.pingSent { // TODO: confirm this
			return http2ErrorProtocol
		}
		return nil
	}
	if now := time.Now(); c.lastPingTime.IsZero() || now.Sub(c.lastPingTime) >= time.Second {
		c.lastPingTime = now
	} else {
		return http2ErrorEnhanceYourCalm
	}
	pongOutFrame := &c.outFrame
	pongOutFrame.streamID = 0
	pongOutFrame.length = 8
	pongOutFrame.kind = http2FramePing
	pongOutFrame.ack = true
	pongOutFrame.payload = pingInFrame.effective()
	err := c.sendOutFrame(pongOutFrame)
	pongOutFrame.zero()
	return err
}
func (c *http2Conn_[H, S]) processGoawayInFrame(goawayInFrame *http2InFrame) error {
	panic("goaway frames should be hijacked by c.receive()")
}
func (c *http2Conn_[H, S]) processWindowUpdateInFrame(windowUpdateInFrame *http2InFrame) error {
	windowSize := binary.BigEndian.Uint32(windowUpdateInFrame.effective())
	if windowSize == 0 || windowSize > _2G1 {
		// The legal range for the increment to the flow-control window is 1 to 2^31 - 1 (2,147,483,647) octets.
		return http2ErrorProtocol
	}
	// TODO
	c.localWindow = int32(windowSize)
	Printf("conn=%d stream=%d windowUpdate=%d\n", c.id, windowUpdateInFrame.streamID, windowSize)
	return nil
}
func (c *http2Conn_[H, S]) processContinuationInFrame(continuationInFrame *http2InFrame) error {
	panic("lonely continuation frames should be rejected priorly")
}

func (c *http2Conn_[H, S]) _updatePeerSettings(settingsInFrame *http2InFrame, asClient bool) error {
	settings := settingsInFrame.effective()
	windowDelta := int32(0)
	for i, j, n := uint16(0), uint16(0), settingsInFrame.length/6; i < n; i++ {
		ident := binary.BigEndian.Uint16(settings[j : j+2])
		value := binary.BigEndian.Uint32(settings[j+2 : j+6])
		switch ident {
		case http2SettingMaxHeaderTableSize:
			c.peerSettings.maxHeaderTableSize = value
			// TODO: immediate Dynamic Table Size Update
		case http2SettingEnablePush:
			if value > 1 || (value == 1 && asClient) {
				return http2ErrorProtocol
			}
			c.peerSettings.enablePush = false // we don't support server push
		case http2SettingMaxConcurrentStreams:
			c.peerSettings.maxConcurrentStreams = value
			// TODO: notify shrink
		case http2SettingInitialWindowSize:
			if value > _2G1 {
				return http2ErrorFlowControl
			}
			windowDelta = int32(value) - c.peerSettings.initialWindowSize
		case http2SettingMaxFrameSize:
			if value < _16K || value > _16M-1 {
				return http2ErrorProtocol
			}
			c.peerSettings.maxFrameSize = value // we don't use this. we only send frames of the minimal size
		case http2SettingMaxHeaderListSize:
			c.peerSettings.maxHeaderListSize = value // this is only an advisory.
		default:
			// RFC 9113 (section 6.5.2): An endpoint that receives a SETTINGS frame with any unknown or unsupported identifier MUST ignore that setting.
		}
		j += 6
	}
	if windowDelta != 0 {
		c.peerSettings.initialWindowSize += windowDelta
		//c._adjustStreamWindows(windowDelta)
	}
	Printf("conn=%d peerSettings=%+v\n", c.id, c.peerSettings)
	return nil
}

func (c *http2Conn_[H, S]) decodeFields(fields []byte, input *[]byte) bool {
	// TODO
	return false
	/*
		var fieldName, lineValue []byte
		var (
			I  uint32 // the decoded integer
			j  int    // index of fields
			ok bool   // decode succeeds or not
		)
		i, n := 0, len(fields)
		for i < n {
			b := fields[i]
			if b >= 0b_1000_0000 { // 6.1. Indexed Header Field Representation
				I, j, ok = hpackDecodeVarint(fields[i:], 7, http2MaxTableIndex)
				if !ok || I == 0 { // The index value of 0 is not used.  It MUST be treated as a decoding error if found in an indexed header field representation.
					Println("decode error")
					return false
				}
				fieldName, lineValue, ok = c.decodeTable.get(I)
				if !ok { // Indices strictly greater than the sum of the lengths of both tables MUST be treated as a decoding error.
					return false
				}
				i += j
			} else if b >= 0b_0010_0000 && b < 0b_0100_0000 { // 6.3. Dynamic Table Size Update
				I, j, ok = hpackDecodeVarint(fields[i:], 5, http2MaxTableSize)
				if !ok {
					Println("decode error")
					return false
				}
				i += j
				Printf("update size=%d\n", I)
			} else { // 0b_01xx_xxxx, 0b_0000_xxxx, 0b_0001_xxxx
				var N int
				if b >= 0b_0100_0000 { // 6.2.1. Literal Header Field with Incremental Indexing
					N = 6
				} else { // 0b_0000_xxxx (6.2.2. Literal Header Field without Indexing), 0b_0001_xxxx (6.2.3. Literal Header Field Never Indexed)
					N = 4
				}
				I, j, ok = hpackDecodeVarint(fields[i:], N, http2MaxTableIndex)
				if !ok {
					println("decode error")
					return false
				}
				i += j
				if I != 0 { // Indexed Name
					fieldName, _, ok = c.decodeTable.get(I)
					if !ok {
						Println("decode error")
						return false
					}
				} else { // New Name
					fieldName, j, ok = hpackDecodeString(input, fields[i:], 255)
					if !ok || len(fieldName) == 0 {
						Println("decode error")
						return false
					}
					i += j
				}
				lineValue, j, ok = hpackDecodeString(input, fields[i:], _16K)
				if !ok {
					Println("decode error")
					return false
				}
				i += j
				if b >= 0b_0100_0000 {
					c.decodeTable.add(fieldName, lineValue)
				} else if b >= 0b_0001_0000 {
					// TODO: never indexed
				}
			}
			Printf("name=%s value=%s\n", fieldName, lineValue)
		}
		return i == n
	*/
}

func (c *http2Conn_[H, S]) sendOutFrame(outFrame *http2OutFrame[S]) error {
	outHeader := outFrame.encodeHeader()
	if len(outFrame.payload) > 0 {
		c.vector = c.fixedVector[0:2]
		c.vector[1] = outFrame.payload
	} else {
		c.vector = c.fixedVector[0:1]
	}
	c.vector[0] = outHeader
	if err := c.setWriteDeadline(); err != nil {
		return err
	}
	n, err := c.writeVec(&c.vector)
	if DebugLevel() >= 2 {
		Printf("--------------------- conn=%d CALL WRITE=%d -----------------------\n", c.id, n)
		Printf("conn=%d ---> %+v\n", c.id, outFrame)
	}
	return err
}

func (c *http2Conn_[H, S]) encodeFields(fields []byte, output *[]byte) {
	// TODO
	// uses c.encodeTable
}

func (c *http2Conn_[H, S]) remoteAddr() net.Addr { return c.netConn.RemoteAddr() }

func (c *http2Conn_[H, S]) setReadDeadline() error {
	if deadline := time.Now().Add(c.holder.ReadTimeout()); deadline.Sub(c.lastRead) >= time.Second {
		if err := c.netConn.SetReadDeadline(deadline); err != nil {
			return err
		}
		c.lastRead = deadline
	}
	return nil
}
func (c *http2Conn_[H, S]) setWriteDeadline() error {
	if deadline := time.Now().Add(c.holder.WriteTimeout()); deadline.Sub(c.lastWrite) >= time.Second {
		if err := c.netConn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		c.lastWrite = deadline
	}
	return nil
}

func (c *http2Conn_[H, S]) readAtLeast(dst []byte, min int) (int, error) {
	return io.ReadAtLeast(c.netConn, dst, min)
}
func (c *http2Conn_[H, S]) write(src []byte) (int, error) { return c.netConn.Write(src) }
func (c *http2Conn_[H, S]) writeVec(srcVec *net.Buffers) (int64, error) {
	return srcVec.WriteTo(c.netConn)
}

// http2Stream
type http2Stream interface { // for *backend2Stream and *server2Stream
	// Imports
	httpStream
	// Methods
	nativeID() uint32   // http/2 native stream id
	getSlot() uint8     // at activeStreamIDs and activeStreams
	setSlot(slot uint8) // at activeStreamIDs and activeStreams
}

// http2Stream_ is a parent.
type http2Stream_[C http2Conn] struct { // for backend2Stream and server2Stream
	// Parent
	httpStream_[C]
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	id           uint32 // the stream id. we use 4 byte instead of int64 (which is used in http/3) to save memory space! see activeStreamIDs
	localWindow  int32  // stream-level window (buffer) size for receiving incoming DATA frames
	remoteWindow int32  // stream-level window (buffer) size for sending outgoing DATA frames
	// Stream states (zeros)
	_http2Stream0 // all values in this struct must be zero by default!
}
type _http2Stream0 struct { // for fast reset, entirely
	slot  uint8 // the slot at s.conn.activeStreamIDs and s.conn.activeStreams
	state uint8 // http2StateOpen, http2StateLocalClosed, http2StateRemoteClosed
}

func (s *http2Stream_[C]) onUse(conn C, id uint32) {
	s.httpStream_.onUse(conn)

	s.id = id
}
func (s *http2Stream_[C]) onEnd() {
	s._http2Stream0 = _http2Stream0{}

	s.httpStream_.onEnd()
}

func (s *http2Stream_[C]) nativeID() uint32   { return s.id }
func (s *http2Stream_[C]) getSlot() uint8     { return s.slot }
func (s *http2Stream_[C]) setSlot(slot uint8) { s.slot = slot }

func (s *http2Stream_[C]) ID() int64 { return int64(s.id) } // implements httpStream interface

func (s *http2Stream_[C]) markBroken()    { s.conn.markBroken() }      // TODO: limit the breakage in the stream?
func (s *http2Stream_[C]) isBroken() bool { return s.conn.isBroken() } // TODO: limit the breakage in the stream?

func (s *http2Stream_[C]) setReadDeadline() error { // for content and trailers i/o only
	// TODO
	return nil
}
func (s *http2Stream_[C]) setWriteDeadline() error {
	// TODO
	return nil
}

func (s *http2Stream_[C]) read(dst []byte) (int, error) { // for content and trailers i/o only
	// TODO
	return 0, nil
}
func (s *http2Stream_[C]) readFull(dst []byte) (int, error) { // for content and trailers i/o only
	// TODO
	return 0, nil
}
func (s *http2Stream_[C]) write(src []byte) (int, error) {
	// TODO
	return 0, nil
}
func (s *http2Stream_[C]) writeVec(srcVec *net.Buffers) (int64, error) {
	// TODO
	return 0, nil
}

// _http2In_ is a mixin.
type _http2In_ struct { // for backend2Response and server2Request
	// Parent
	*_httpIn_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *_http2In_) onUse(parent *_httpIn_) {
	r._httpIn_ = parent
}
func (r *_http2In_) onEnd() {
	r._httpIn_ = nil
}

func (r *_http2In_) _growHeaders(size int32) bool {
	edge := r.inputEdge + size      // size is ensured to not overflow
	if edge < int32(cap(r.input)) { // fast path
		return true
	}
	if edge > _16K { // exceeds the max header section limit
		return false
	}
	input := GetNK(int64(edge)) // 4K/16K
	copy(input, r.input[0:r.inputEdge])
	if cap(r.input) != cap(r.stockInput) {
		PutNK(r.input)
	}
	r.input = input
	return true
}

func (r *_http2In_) readContent() (data []byte, err error) {
	// TODO
	return
}
func (r *_http2In_) _readSizedContent() ([]byte, error) {
	// r.stream.setReadDeadline() // may be called multiple times during the reception of the sized content
	return nil, nil
}
func (r *_http2In_) _readVagueContent() ([]byte, error) {
	// r.stream.setReadDeadline() // may be called multiple times during the reception of the vague content
	return nil, nil
}

// _http2Out_ is a mixin.
type _http2Out_ struct { // for backend2Request and server2Response
	// Parent
	*_httpOut_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *_http2Out_) onUse(parent *_httpOut_) {
	r._httpOut_ = parent
}
func (r *_http2Out_) onEnd() {
	r._httpOut_ = nil
}

func (r *_http2Out_) addHeader(name []byte, value []byte) bool {
	// TODO
	return false
}
func (r *_http2Out_) header(name []byte) (value []byte, ok bool) {
	// TODO
	return
}
func (r *_http2Out_) hasHeader(name []byte) bool {
	// TODO
	return false
}
func (r *_http2Out_) delHeader(name []byte) (deleted bool) {
	// TODO
	return false
}
func (r *_http2Out_) delHeaderAt(i uint8) {
	// TODO
}

func (r *_http2Out_) sendChain() error {
	// TODO
	return nil
}
func (r *_http2Out_) _sendEntireChain() error {
	// TODO
	return nil
}
func (r *_http2Out_) _sendSingleRange() error {
	// TODO
	return nil
}
func (r *_http2Out_) _sendMultiRanges() error {
	// TODO
	return nil
}

func (r *_http2Out_) echoChain() error {
	// TODO
	return nil
}

func (r *_http2Out_) addTrailer(name []byte, value []byte) bool {
	// TODO
	return false
}
func (r *_http2Out_) trailer(name []byte) (value []byte, ok bool) {
	// TODO
	return
}
func (r *_http2Out_) trailers() []byte {
	// TODO
	return nil
}

func (r *_http2Out_) proxyPassBytes(data []byte) error { return r.writeBytes(data) }

func (r *_http2Out_) finalizeVague2() error {
	// TODO
	if r.numTrailerFields == 1 { // no trailer section
	} else { // with trailer section
	}
	return nil
}

func (r *_http2Out_) writeHeaders() error { // used by echo and pass
	// TODO
	r.outputEdge = 0 // now that header fields are all sent, r.output will be used by trailer fields (if any), so reset it.
	return nil
}
func (r *_http2Out_) writePiece(piece *Piece, vague bool) error {
	// TODO
	return nil
}
func (r *_http2Out_) _writeTextPiece(piece *Piece) error {
	// TODO
	return nil
}
func (r *_http2Out_) _writeFilePiece(piece *Piece) error {
	// TODO
	// r.stream.setWriteDeadline() // for _writeFilePiece
	// r.stream.write() or r.stream.writeVec()
	return nil
}
func (r *_http2Out_) writeVector() error {
	// TODO
	// r.stream.setWriteDeadline() // for writeVector
	// r.stream.writeVec()
	return nil
}
func (r *_http2Out_) writeBytes(data []byte) error {
	// TODO
	// r.stream.setWriteDeadline() // for writeBytes
	// r.stream.write()
	return nil
}

// _http2Socket_ is a mixin.
type _http2Socket_ struct { // for backend2Socket and server2Socket
	// Parent
	*_httpSocket_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (s *_http2Socket_) onUse(parent *_httpSocket_) {
	s._httpSocket_ = parent
}
func (s *_http2Socket_) onEnd() {
	s._httpSocket_ = nil
}

func (s *_http2Socket_) todo2() {
	s.todo()
}

////////////////////////////////////////////////////////////////

const ( // HTTP/2 sizes and limits for both of our HTTP/2 server and HTTP/2 backend
	http2MaxFrameSize         = _16K // currently hardcoded. must <= _64K1 - 9
	http2MaxTableSize         = _4K  // currently hardcoded
	http2MaxConcurrentStreams = 127  // currently hardcoded. don't change this
)

const ( // HTTP/2 frame kinds
	http2FrameData         = 0x0
	http2FrameFields       = 0x1 // a.k.a. headers
	http2FramePriority     = 0x2 // deprecated. ignored on receiving, and we won't send
	http2FrameResetStream  = 0x3 // a.k.a. rst_stream
	http2FrameSettings     = 0x4
	http2FramePushPromise  = 0x5 // not supported
	http2FramePing         = 0x6
	http2FrameGoaway       = 0x7
	http2FrameWindowUpdate = 0x8
	http2FrameContinuation = 0x9
	http2NumFrameKinds     = 10
)

const ( // HTTP/2 stream states. Server Push related states are not supported
	http2StateIdle         = 0 // must be 0, default value
	http2StateOpen         = 1
	http2StateRemoteClosed = 2
	http2StateLocalClosed  = 3
	http2StateClosed       = 4
)

const ( // HTTP/2 settings
	http2SettingMaxHeaderTableSize   = 0x1
	http2SettingEnablePush           = 0x2
	http2SettingMaxConcurrentStreams = 0x3
	http2SettingInitialWindowSize    = 0x4
	http2SettingMaxFrameSize         = 0x5
	http2SettingMaxHeaderListSize    = 0x6
)

// http2Settings
type http2Settings struct {
	maxHeaderTableSize   uint32 // 0x1
	enablePush           bool   // 0x2, always false as we don't support server push
	maxConcurrentStreams uint32 // 0x3
	initialWindowSize    int32  // 0x4
	maxFrameSize         uint32 // 0x5
	maxHeaderListSize    uint32 // 0x6
}

var http2InitialSettings = http2Settings{ // default settings for both backend2Conn and server2Conn
	maxHeaderTableSize:   _4K,   // the table size that we allow the remote peer to use
	enablePush:           false, // we don't support server push
	maxConcurrentStreams: 127,   // the number that we allow the remote peer to initiate
	initialWindowSize:    _64K1, // this requires the size of content buffer must up to 64K1
	maxFrameSize:         _16K,  // the size that we allow the remote peer to use
	maxHeaderListSize:    _16K,  // the size that we allow the remote peer to use
}

const ( // HTTP/2 error codes
	http2CodeNoError            = 0x0 // The associated condition is not a result of an error. For example, a GOAWAY might include this code to indicate graceful shutdown of a connection.
	http2CodeProtocol           = 0x1 // The endpoint detected an unspecific protocol error. This error is for use when a more specific error code is not available.
	http2CodeInternal           = 0x2 // The endpoint encountered an unexpected internal error.
	http2CodeFlowControl        = 0x3 // The endpoint detected that its peer violated the flow-control protocol.
	http2CodeSettingsTimeout    = 0x4 // The endpoint sent a SETTINGS frame but did not receive a response in a timely manner. See Section 6.5.3 ("Settings Synchronization").
	http2CodeStreamClosed       = 0x5 // The endpoint received a frame after a stream was half-closed.
	http2CodeFrameSize          = 0x6 // The endpoint received a frame with an invalid size.
	http2CodeRefusedStream      = 0x7 // The endpoint refused the stream prior to performing any application processing (see Section 8.7 for details).
	http2CodeCancel             = 0x8 // The endpoint uses this error code to indicate that the stream is no longer needed.
	http2CodeCompression        = 0x9 // The endpoint is unable to maintain the field section compression context for the connection.
	http2CodeConnect            = 0xa // The connection established in response to a CONNECT request (Section 8.5) was reset or abnormally closed.
	http2CodeEnhanceYourCalm    = 0xb // The endpoint detected that its peer is exhibiting a behavior that might be generating excessive load.
	http2CodeInadequateSecurity = 0xc // The underlying transport has properties that do not meet minimum security requirements (see Section 9.2).
	http2CodeHTTP11Required     = 0xd // The endpoint requires that HTTP/1.1 be used instead of HTTP/2.
	http2NumErrorCodes          = 14  // Unknown or unsupported error codes MUST NOT trigger any special behavior. These MAY be treated by an implementation as being equivalent to INTERNAL_ERROR.
)

// http2Error denotes both connection error and stream error.
type http2Error uint32

var ( // HTTP/2 errors
	http2ErrorNoError            http2Error = http2CodeNoError
	http2ErrorProtocol           http2Error = http2CodeProtocol
	http2ErrorInternal           http2Error = http2CodeInternal
	http2ErrorFlowControl        http2Error = http2CodeFlowControl
	http2ErrorSettingsTimeout    http2Error = http2CodeSettingsTimeout
	http2ErrorStreamClosed       http2Error = http2CodeStreamClosed
	http2ErrorFrameSize          http2Error = http2CodeFrameSize
	http2ErrorRefusedStream      http2Error = http2CodeRefusedStream
	http2ErrorCancel             http2Error = http2CodeCancel
	http2ErrorCompression        http2Error = http2CodeCompression
	http2ErrorConnect            http2Error = http2CodeConnect
	http2ErrorEnhanceYourCalm    http2Error = http2CodeEnhanceYourCalm
	http2ErrorInadequateSecurity http2Error = http2CodeInadequateSecurity
	http2ErrorHTTP11Required     http2Error = http2CodeHTTP11Required
)

func (e http2Error) Error() string {
	if e < http2NumErrorCodes {
		return http2CodeTexts[e]
	}
	return "UNKNOWN_ERROR"
}

var http2CodeTexts = [...]string{
	http2CodeNoError:            "NO_ERROR",
	http2CodeProtocol:           "PROTOCOL_ERROR",
	http2CodeInternal:           "INTERNAL_ERROR",
	http2CodeFlowControl:        "FLOW_CONTROL_ERROR",
	http2CodeSettingsTimeout:    "SETTINGS_TIMEOUT",
	http2CodeStreamClosed:       "STREAM_CLOSED",
	http2CodeFrameSize:          "FRAME_SIZE_ERROR",
	http2CodeRefusedStream:      "REFUSED_STREAM",
	http2CodeCancel:             "CANCEL",
	http2CodeCompression:        "COMPRESSION_ERROR",
	http2CodeConnect:            "CONNECT_ERROR",
	http2CodeEnhanceYourCalm:    "ENHANCE_YOUR_CALM",
	http2CodeInadequateSecurity: "INADEQUATE_SECURITY",
	http2CodeHTTP11Required:     "HTTP_1_1_REQUIRED",
}

func hpackDecodeVarint(fields []byte, N int, max uint32) (I uint32, j int, ok bool) { // ok = false if fields is malformed or result > max
	// Pseudocode to decode an integer I is as follows:
	//
	// decode I from the next N bits
	// if I < 2^N - 1, return I
	// else
	//     M = 0
	//     repeat
	//         B = next octet
	//         I = I + (B & 127) * 2^M
	//         M = M + 7
	//     while B & 128 == 128
	//     return I
	l := len(fields)
	if l == 0 {
		return 0, 0, false
	}
	K := uint32(1<<N) - 1
	I = uint32(fields[0]) & K
	if I < K {
		return I, 1, I <= max
	}
	j = 1
	for M := 0; j < l; M += 7 { // M -> 7,14,21,28
		B := fields[j]
		j++
		I += uint32(B&0x7F) << M // M = 0,7,14,21,28
		if I > max {
			break
		}
		if B < 0x80 {
			return I, j, true
		}
	}
	return I, j, false
}
func hpackDecodeString(input []byte, fields []byte, max uint32) (i int, j int, ok bool) { // ok = false if fields is malformed or length of result string > max
	I, j, ok := hpackDecodeVarint(fields, 7, max)
	if !ok {
		return 0, j, false
	}
	H := fields[0] >= 0x80
	fields = fields[j:]
	if I > uint32(len(fields)) {
		return 0, j, false
	}
	j += int(I)
	if H { // the string is huffman encoded, needs decoding
		i, ok := httpHuffmanDecode(input, fields[:I])
		return i, j, ok
	}
	copy(input, fields[:I])
	return j, j, true
}

func hpackEncodeVarint(fields []byte, I uint32, N int) (int, bool) { // ok = false if fields is not large enough
	// Pseudocode to encode an integer I is as follows:
	//
	// if I < 2^N - 1, encode I on N bits
	// else
	//     encode (2^N - 1) on N bits
	//     I = I - (2^N - 1)
	//     while I >= 128
	//          encode (I % 128 + 128) on 8 bits
	//          I = I / 128
	//     encode I on 8 bits
	l := len(fields)
	if l == 0 {
		return 0, false
	}
	K := uint32(1<<N) - 1
	if I < K {
		fields[0] = byte(I)
		return 1, true
	}
	fields[0] = byte(K)
	j := 1
	for I -= K; I >= 0x80 && j < l; I /= 0x80 {
		fields[j] = byte(I) | 0x80
		j++
	}
	if j == l {
		return j, false
	}
	fields[j] = byte(I)
	return j + 1, true
}
func hpackEncodeString(fields []byte, output []byte) (int, bool) { // ok = false if fields is not large enough
	I := len(output)
	if I == 0 {
		return 0, true
	}
	n := httpHuffmanLength(output)
	H := n < I
	if !H {
		n = I
	}
	j, ok := hpackEncodeVarint(fields, uint32(n), 7)
	if !ok {
		return j, false
	}
	if H {
		fields[0] |= 0x80
	}
	fields = fields[j:]
	if len(fields) < n {
		return j, false
	}
	if H {
		httpHuffmanEncode(fields, output)
	} else {
		copy(fields, output)
	}
	return j + n, true
}

// hpackTableEntry is an HPACK table entry.
type hpackTableEntry struct { // 8 bytes
	nameHash  uint16 // name hash
	nameFrom  uint16 // name edge at nameFrom+nameSize
	nameSize  uint8  // must <= 255
	isStatic  bool   // ...
	valueEdge uint16 // value: [nameFrom+nameSize:valueEdge]
}

var hpackStaticBytes = []byte(":authority:methodGET:methodPOST:path/:path/index.html:schemehttp:schemehttps:status200:status204:status206:status304:status400:status404:status500accept-charsetaccept-encodinggzip, deflateaccept-languageaccept-rangesacceptaccess-control-allow-originageallowauthorizationcache-controlcontent-dispositioncontent-encodingcontent-languagecontent-lengthcontent-locationcontent-rangecontent-typecookiedateetagexpectexpiresfromhostif-matchif-modified-sinceif-none-matchif-rangeif-unmodified-sincelast-modifiedlinklocationmax-forwardsproxy-authenticateproxy-authorizationrangerefererrefreshretry-afterserverset-cookiestrict-transport-securitytransfer-encodinguser-agentvaryviawww-authenticate")

// hpackStaticTable is the HPACK static table.
var hpackStaticTable = [...]hpackTableEntry{
	0:  {0, 0, 0, true, 0},         // empty, never used
	1:  {1059, 0, 10, true, 10},    // :authority=
	2:  {699, 10, 7, true, 20},     // :method=GET
	3:  {699, 20, 7, true, 31},     // :method=POST
	4:  {487, 31, 5, true, 37},     // :path=/
	5:  {487, 37, 5, true, 53},     // :path=/index.html
	6:  {687, 53, 7, true, 64},     // :scheme=http
	7:  {687, 64, 7, true, 76},     // :scheme=https
	8:  {734, 76, 7, true, 86},     // :status=200
	9:  {734, 86, 7, true, 96},     // :status=204
	10: {734, 96, 7, true, 106},    // :status=206
	11: {734, 106, 7, true, 116},   // :status=304
	12: {734, 116, 7, true, 126},   // :status=400
	13: {734, 126, 7, true, 136},   // :status=404
	14: {734, 136, 7, true, 146},   // :status=500
	15: {1415, 146, 14, true, 160}, // accept-charset=
	16: {1508, 160, 15, true, 188}, // accept-encoding=gzip, deflate
	17: {1505, 188, 15, true, 203}, // accept-language=
	18: {1309, 203, 13, true, 216}, // accept-ranges=
	19: {624, 216, 6, true, 222},   // accept=
	20: {2721, 222, 27, true, 249}, // access-control-allow-origin=
	21: {301, 249, 3, true, 252},   // age=
	22: {543, 252, 5, true, 257},   // allow=
	23: {1425, 257, 13, true, 270}, // authorization=
	24: {1314, 270, 13, true, 283}, // cache-control=
	25: {2013, 283, 19, true, 302}, // content-disposition=
	26: {1647, 302, 16, true, 318}, // content-encoding=
	27: {1644, 318, 16, true, 334}, // content-language=
	28: {1450, 334, 14, true, 348}, // content-length=
	29: {1665, 348, 16, true, 364}, // content-location=
	30: {1333, 364, 13, true, 377}, // content-range=
	31: {1258, 377, 12, true, 389}, // content-type=
	32: {634, 389, 6, true, 395},   // cookie=
	33: {414, 395, 4, true, 399},   // date=
	34: {417, 399, 4, true, 403},   // etag=
	35: {649, 403, 6, true, 409},   // expect=
	36: {768, 409, 7, true, 416},   // expires=
	37: {436, 416, 4, true, 420},   // from=
	38: {446, 420, 4, true, 424},   // host=
	39: {777, 424, 8, true, 432},   // if-match=
	40: {1660, 432, 17, true, 449}, // if-modified-since=
	41: {1254, 449, 13, true, 462}, // if-none-match=
	42: {777, 462, 8, true, 470},   // if-range=
	43: {1887, 470, 19, true, 489}, // if-unmodified-since=
	44: {1314, 489, 13, true, 502}, // last-modified=
	45: {430, 502, 4, true, 506},   // link=
	46: {857, 506, 8, true, 514},   // location=
	47: {1243, 514, 12, true, 526}, // max-forwards=
	48: {1902, 526, 18, true, 544}, // proxy-authenticate=
	49: {2048, 544, 19, true, 563}, // proxy-authorization=
	50: {525, 563, 5, true, 568},   // range=
	51: {747, 568, 7, true, 575},   // referer=
	52: {751, 575, 7, true, 582},   // refresh=
	53: {1141, 582, 11, true, 593}, // retry-after=
	54: {663, 593, 6, true, 599},   // server=
	55: {1011, 599, 10, true, 609}, // set-cookie=
	56: {2648, 609, 25, true, 634}, // strict-transport-security=
	57: {1753, 634, 17, true, 651}, // transfer-encoding=
	58: {1019, 651, 10, true, 661}, // user-agent=
	59: {450, 661, 4, true, 665},   // vary=
	60: {320, 665, 3, true, 668},   // via=
	61: {1681, 668, 16, true, 684}, // www-authenticate=
}

const hpackMaxTableIndex = 61 + 124 // static[1-61] + dynamic[62-185]

// hpackTable
type hpackTable struct { // <= 5KiB
	tableSize  uint32                       // <= http2MaxTableSize
	freeSize   uint32                       // <= tableSize
	iNewest    uint32                       // append to t.entries[t.iNewest]
	iOldest    uint32                       // evict from t.entries[t.iOldest]
	numEntries uint32                       // num of current entries
	maxEntries uint32                       // cap(entries). max num = floor(http2MaxTableSize/(1+32)) = 124, where 1 is the size of a shortest field
	entries    [124]hpackTableEntry         // implemented as a circular buffer: https://en.wikipedia.org/wiki/Circular_buffer
	content    [http2MaxTableSize - 32]byte // the content buffer. http2MaxTableSize-32 is the upper limit size that the remote encoder can occupy
}

func (t *hpackTable) init() {
	t.tableSize = http2MaxTableSize
	t.freeSize = t.tableSize
	t.iNewest = 0
	t.iOldest = 0
	t.numEntries = 0
	t.maxEntries = uint32(cap(t.entries))
}

func (t *hpackTable) add(name []byte, value []byte) bool { // name is not empty. sizes of name and value are limited
	if t.numEntries == t.maxEntries { // too many entries
		return false
	}
	nameSize, valueSize := uint32(len(name)), uint32(len(value))
	entrySize := nameSize + valueSize + 32 // won't overflow
	// Before a new entry is added to the dynamic table, entries are evicted
	// from the end of the dynamic table until the size of the dynamic table
	// is less than or equal to (maximum size - new entry size) or until the
	// table is empty.
	//
	// If the size of the new entry is less than or equal to the maximum
	// size, that entry is added to the table.  It is not an error to
	// attempt to add an entry that is larger than the maximum size; an
	// attempt to add an entry larger than the maximum size causes the table
	// to be emptied of all existing entries and results in an empty table.
	if entrySize > t.tableSize {
		t.freeSize = t.tableSize
		t.numEntries = 0
		t.iOldest = t.iNewest
		return true
	}
	for t.freeSize < entrySize {
		t._evictOne()
	}
	t.freeSize -= entrySize
	var newEntry hpackTableEntry
	if t.numEntries > 0 {
		newEntry.nameFrom = t.entries[t.iNewest].valueEdge
		if t.iNewest++; t.iNewest == t.maxEntries {
			t.iNewest = 0 // wrap around
		}
	} else { // empty table. starts from 0
		newEntry.nameFrom = 0
	}
	newEntry.nameSize = uint8(nameSize)
	nameEdge := newEntry.nameFrom + uint16(newEntry.nameSize)
	newEntry.valueEdge = nameEdge + uint16(valueSize)
	copy(t.content[newEntry.nameFrom:nameEdge], name)
	if valueSize > 0 {
		copy(t.content[nameEdge:newEntry.valueEdge], value)
	}
	t.numEntries++
	t.entries[t.iNewest] = newEntry
	return true
}
func (t *hpackTable) get(index uint32) (name []byte, value []byte, ok bool) {
	if index >= t.numEntries {
		return nil, nil, false
	}
	if t.iNewest <= t.iOldest && index > t.iNewest {
		index -= t.iNewest
		index = t.maxEntries - index
	} else {
		index = t.iNewest - index
	}
	entry := t.entries[index]
	nameEdge := entry.nameFrom + uint16(entry.nameSize)
	return t.content[entry.nameFrom:nameEdge], t.content[nameEdge:entry.valueEdge], true
}
func (t *hpackTable) resize(newMaxSize uint32) { // newMaxSize must <= http2MaxTableSize
	if newMaxSize > http2MaxTableSize {
		BugExitln("newMaxSize out of range")
	}
	if newMaxSize >= t.tableSize {
		t.freeSize += newMaxSize - t.tableSize
	} else {
		for usedSize := t.tableSize - t.freeSize; usedSize > newMaxSize; usedSize = t.tableSize - t.freeSize {
			t._evictOne()
		}
		t.freeSize -= t.tableSize - newMaxSize
	}
	t.tableSize = newMaxSize
}
func (t *hpackTable) _evictOne() {
	if t.numEntries == 0 {
		BugExitln("no entries to evict!")
	}
	evictee := &t.entries[t.iOldest]
	t.freeSize += uint32(evictee.valueEdge - evictee.nameFrom + 32)
	if t.iOldest++; t.iOldest == t.maxEntries {
		t.iOldest = 0
	}
	if t.numEntries--; t.numEntries == 0 {
		t.iNewest = t.iOldest
	}
}

var http2FreeSlots = [http2MaxConcurrentStreams]uint8{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
	49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
	65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
	81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
	97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
	113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126,
}

// http2Buffer is the HTTP/2 incoming buffer.
type http2Buffer struct {
	buf [9 + http2MaxFrameSize]byte // frame header + frame payload
	ref atomic.Int32
}

var poolHTTP2Buffer sync.Pool

func getHTTP2Buffer() *http2Buffer {
	var inBuffer *http2Buffer
	if x := poolHTTP2Buffer.Get(); x == nil {
		inBuffer = new(http2Buffer)
	} else {
		inBuffer = x.(*http2Buffer)
	}
	return inBuffer
}
func putHTTP2Buffer(inBuffer *http2Buffer) { poolHTTP2Buffer.Put(inBuffer) }

func (b *http2Buffer) size() uint16  { return uint16(cap(b.buf)) }
func (b *http2Buffer) getRef() int32 { return b.ref.Load() }
func (b *http2Buffer) incRef()       { b.ref.Add(1) }
func (b *http2Buffer) decRef() {
	if b.ref.Add(-1) == 0 {
		if DebugLevel() >= 1 {
			Printf("putHTTP2Buffer ref=%d\n", b.ref.Load())
		}
		putHTTP2Buffer(b)
	}
}

// http2InFrame is the HTTP/2 incoming frame.
type http2InFrame struct { // 24 bytes
	inBuffer  *http2Buffer // the inBuffer that holds payload
	streamID  uint32       // the real type is uint31
	length    uint16       // length of payload. the real type is uint24, but we never allow sizes out of range of uint16, so use uint16
	kind      uint8        // see http2FrameXXX
	endFields bool         // is END_FIELDS flag set?
	endStream bool         // is END_STREAM flag set?
	ack       bool         // is ACK flag set?
	padded    bool         // is PADDED flag set?
	priority  bool         // is PRIORITY flag set?
	efctFrom  uint16       // (effective) payload from
	efctEdge  uint16       // (effective) payload edge
}

func (f *http2InFrame) zero() { *f = http2InFrame{} }

func (f *http2InFrame) decodeHeader(inHeader []byte) error {
	inHeader[5] &= 0x7f // ignore the reserved bit
	f.streamID = binary.BigEndian.Uint32(inHeader[5:9])
	if f.streamID != 0 && f.streamID&1 == 0 { // we don't support server push, so only odd stream ids are allowed
		return http2ErrorProtocol
	}
	length := uint32(inHeader[0])<<16 | uint32(inHeader[1])<<8 | uint32(inHeader[2])
	if length > http2MaxFrameSize {
		// An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE,
		// exceeds any limit defined for the frame type, or is too small to contain mandatory frame data.
		return http2ErrorFrameSize
	}
	f.length = uint16(length)
	f.kind = inHeader[3]
	flags := inHeader[4]
	f.endFields = flags&0x04 != 0 && (f.kind == http2FrameFields || f.kind == http2FrameContinuation)
	f.endStream = flags&0x01 != 0 && (f.kind == http2FrameData || f.kind == http2FrameFields)
	f.ack = flags&0x01 != 0 && (f.kind == http2FrameSettings || f.kind == http2FramePing)
	f.padded = flags&0x08 != 0 && (f.kind == http2FrameData || f.kind == http2FrameFields)
	f.priority = flags&0x20 != 0 && f.kind == http2FrameFields
	return nil
}

func (f *http2InFrame) isUnknown() bool   { return f.kind >= http2NumFrameKinds }
func (f *http2InFrame) effective() []byte { return f.inBuffer.buf[f.efctFrom:f.efctEdge] } // effective payload

var http2InFrameCheckers = [http2NumFrameKinds]func(*http2InFrame) error{ // for known frames
	(*http2InFrame).checkAsData,
	(*http2InFrame).checkAsFields,
	(*http2InFrame).checkAsPriority,
	(*http2InFrame).checkAsResetStream,
	(*http2InFrame).checkAsSettings,
	(*http2InFrame).checkAsPushPromise,
	(*http2InFrame).checkAsPing,
	(*http2InFrame).checkAsGoaway,
	(*http2InFrame).checkAsWindowUpdate,
	(*http2InFrame).checkAsContinuation,
}

func (f *http2InFrame) checkAsData() error {
	var minLength uint16 = 0 // Data (..)
	if f.padded {
		minLength += 1 // Pad Length (8)
	}
	if f.length < minLength {
		return http2ErrorFrameSize
	}
	if f.streamID == 0 {
		return http2ErrorProtocol
	}
	var padLength, othersLen uint16 = 0, 0
	if f.padded {
		padLength = uint16(f.inBuffer.buf[f.efctFrom])
		othersLen += 1
		f.efctFrom += 1
	}
	if padLength > 0 { // drop padding
		if othersLen+padLength >= f.length {
			return http2ErrorProtocol
		}
		f.efctEdge -= padLength
	}
	return nil
}
func (f *http2InFrame) checkAsFields() error {
	var minLength uint16 = 1 // Field Block Fragment
	if f.padded {
		minLength += 1 // Pad Length (8)
	}
	if f.priority {
		minLength += 5 // Exclusive (1) + Stream Dependency (31) + Weight (8)
	}
	if f.length < minLength {
		return http2ErrorFrameSize
	}
	if f.streamID == 0 {
		return http2ErrorProtocol
	}
	var padLength, othersLen uint16 = 0, 0
	if f.padded { // skip pad length byte
		padLength = uint16(f.inBuffer.buf[f.efctFrom])
		othersLen += 1
		f.efctFrom += 1
	}
	if f.priority { // skip stream dependency and weight
		othersLen += 5
		f.efctFrom += 5
	}
	if padLength > 0 { // drop padding
		if othersLen+padLength >= f.length {
			return http2ErrorProtocol
		}
		f.efctEdge -= padLength
	}
	return nil
}
func (f *http2InFrame) checkAsPriority() error {
	if f.length != 5 {
		return http2ErrorFrameSize
	}
	if f.streamID == 0 {
		return http2ErrorProtocol
	}
	return nil
}
func (f *http2InFrame) checkAsResetStream() error {
	if f.length != 4 {
		return http2ErrorFrameSize
	}
	if f.streamID == 0 {
		return http2ErrorProtocol
	}
	return nil
}
func (f *http2InFrame) checkAsSettings() error {
	if f.length%6 != 0 || f.length > 48 { // we allow 8 defined settings.
		return http2ErrorFrameSize
	}
	if f.streamID != 0 {
		return http2ErrorProtocol
	}
	if f.ack && f.length != 0 {
		return http2ErrorFrameSize
	}
	return nil
}
func (f *http2InFrame) checkAsPushPromise() error {
	return http2ErrorProtocol // we don't support server push
}
func (f *http2InFrame) checkAsPing() error {
	if f.length != 8 {
		return http2ErrorFrameSize
	}
	if f.streamID != 0 {
		return http2ErrorProtocol
	}
	return nil
}
func (f *http2InFrame) checkAsGoaway() error {
	if f.length < 8 {
		return http2ErrorFrameSize
	}
	if f.streamID != 0 {
		return http2ErrorProtocol
	}
	return nil
}
func (f *http2InFrame) checkAsWindowUpdate() error {
	if f.length != 4 {
		return http2ErrorFrameSize
	}
	return nil
}
func (f *http2InFrame) checkAsContinuation() error {
	return http2ErrorProtocol // continuation frames cannot be alone. we coalesce continuation frames on receiving fields frame
}

// http2OutFrame is the HTTP/2 outgoing frame.
type http2OutFrame[S http2Stream] struct { // 64 bytes
	streamID  uint32   // id of stream, duplicate for convenience
	length    uint16   // length of payload. the real type is uint24, but we never use sizes out of range of uint16, so use uint16
	kind      uint8    // see http2FrameXXX. WARNING: http2FramePushPromise and http2FrameContinuation are NOT allowed! we don't use them.
	endFields bool     // is END_FIELDS flag set?
	endStream bool     // is END_STREAM flag set?
	ack       bool     // is ACK flag set?
	padded    bool     // is PADDED flag set?
	header    [9]byte  // frame header is encoded here
	outBuffer [12]byte // small payload of the frame is placed here temporarily
	payload   []byte   // refers to the payload
	stream    S        // the http/2 stream to which the frame belongs. nil if the frame belongs to conneciton
}

func (f *http2OutFrame[S]) zero() { *f = http2OutFrame[S]{} }

func (f *http2OutFrame[S]) encodeHeader() (outHeader []byte) { // caller must ensure the frame is legal.
	if f.streamID > 0x7fffffff {
		BugExitln("stream id too large")
	}
	if f.length > http2MaxFrameSize {
		BugExitln("frame length too large")
	}
	if f.kind == http2FramePushPromise || f.kind == http2FrameContinuation {
		BugExitln("push promise and continuation are not allowed as out frame")
	}
	outHeader = f.header[:]
	outHeader[0], outHeader[1], outHeader[2] = byte(f.length>>16), byte(f.length>>8), byte(f.length)
	outHeader[3] = f.kind
	flags := uint8(0x00)
	if f.endFields && f.kind == http2FrameFields { // we never use http2FrameContinuation
		flags |= 0x04
	}
	if f.endStream && (f.kind == http2FrameData || f.kind == http2FrameFields) {
		flags |= 0x01
	}
	if f.ack && (f.kind == http2FrameSettings || f.kind == http2FramePing) {
		flags |= 0x01
	}
	if f.padded && (f.kind == http2FrameData || f.kind == http2FrameFields) {
		flags |= 0x08
	}
	outHeader[4] = flags
	binary.BigEndian.PutUint32(outHeader[5:9], f.streamID)
	return
}
