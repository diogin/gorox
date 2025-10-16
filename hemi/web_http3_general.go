// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// HTTP/3 general implementation. See RFC 9114, RFC 9204, and RFC 9220.

// Server Push is not supported because it's rarely used. Chrome and Firefox even removed it.

package hemi

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/diogin/gorox/hemi/library/gotcp2"
)

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
