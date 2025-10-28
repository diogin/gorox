// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// HTTP/1 implementation. See RFC 9112 and RFC 6455.

// For HTTP/1 servers, both HTTP/1.0 and HTTP/1.1 are supported. Pipelining is supported but not optimized because it's rarely used.
// For HTTP/1 backends, only HTTP/1.1 is used, so HTTP/1 backends MUST support HTTP/1.1. Pipelining is not used.

package hemi

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

// http1Conn
type http1Conn interface { // for *backend1Conn and *server1Conn
	// Imports
	httpConn
	// Methods
	setReadDeadline() error
	setWriteDeadline() error
	read(dst []byte) (int, error)
	readFull(dst []byte) (int, error)
	write(src []byte) (int, error)
	writeVec(srcVec *net.Buffers) (int64, error)
}

// http1Conn_ is a parent.
type http1Conn_[H httpHolder, S http1Stream] struct { // for backend1Conn and server1Conn
	// Parent
	httpConn_[H]
	// Conn states (stocks)
	// Conn states (controlled)
	// Conn states (non-zeros)
	netConn    net.Conn        // *net.TCPConn, *tls.Conn, *net.UnixConn
	rawConn    syscall.RawConn // for syscall, only usable when netConn is TCP/UDS
	persistent bool            // keep the connection after current stream? true by default, will be changed by "connection: close" header field received from the remote side
	// Conn states (zeros)
	streamID  int64     // next stream id
	lastWrite time.Time // deadline of last write operation
	lastRead  time.Time // deadline of last read operation
}

func (c *http1Conn_[H, S]) onGet(id int64, holder H, netConn net.Conn, rawConn syscall.RawConn) {
	c.httpConn_.onGet(id, holder)

	c.netConn = netConn
	c.rawConn = rawConn
	c.persistent = true
}
func (c *http1Conn_[H, S]) onPut() {
	c.netConn = nil
	c.rawConn = nil
	c.streamID = 0
	c.lastWrite = time.Time{}
	c.lastRead = time.Time{}

	c.httpConn_.onPut()
}

func (c *http1Conn_[H, S]) nextStreamID() int64 {
	c.streamID++
	return c.streamID
}

func (c *http1Conn_[H, S]) remoteAddr() net.Addr { return c.netConn.RemoteAddr() }

func (c *http1Conn_[H, S]) setReadDeadline() error {
	if deadline := time.Now().Add(c.holder.ReadTimeout()); deadline.Sub(c.lastRead) >= time.Second {
		if err := c.netConn.SetReadDeadline(deadline); err != nil {
			return err
		}
		c.lastRead = deadline
	}
	return nil
}
func (c *http1Conn_[H, S]) setWriteDeadline() error {
	if deadline := time.Now().Add(c.holder.WriteTimeout()); deadline.Sub(c.lastWrite) >= time.Second {
		if err := c.netConn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		c.lastWrite = deadline
	}
	return nil
}

func (c *http1Conn_[H, S]) read(dst []byte) (int, error)     { return c.netConn.Read(dst) }
func (c *http1Conn_[H, S]) readFull(dst []byte) (int, error) { return io.ReadFull(c.netConn, dst) }
func (c *http1Conn_[H, S]) write(src []byte) (int, error)    { return c.netConn.Write(src) }
func (c *http1Conn_[H, S]) writeVec(srcVec *net.Buffers) (int64, error) {
	return srcVec.WriteTo(c.netConn)
}

// http1Stream
type http1Stream interface { // for *backend1Stream and *server1Stream
	// Imports
	httpStream
	// Methods
}

// http1Stream_ is a parent.
type http1Stream_[C http1Conn] struct { // for backend1Stream and server1Stream
	// Parent
	httpStream_[C]
	// Assocs
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	id int64 // the stream id
	// Stream states (zeros)
}

func (s *http1Stream_[C]) onUse(conn C, id int64) {
	s.httpStream_.onUse(conn)

	s.id = id
}
func (s *http1Stream_[C]) onEnd() {
	s.httpStream_.onEnd()
}

func (s *http1Stream_[C]) ID() int64 { return s.id }

func (s *http1Stream_[C]) markBroken()    { s.conn.markBroken() }
func (s *http1Stream_[C]) isBroken() bool { return s.conn.isBroken() }

func (s *http1Stream_[C]) setReadDeadline() error  { return s.conn.setReadDeadline() }
func (s *http1Stream_[C]) setWriteDeadline() error { return s.conn.setWriteDeadline() }

func (s *http1Stream_[C]) read(dst []byte) (int, error)     { return s.conn.read(dst) }
func (s *http1Stream_[C]) readFull(dst []byte) (int, error) { return s.conn.readFull(dst) }
func (s *http1Stream_[C]) write(src []byte) (int, error)    { return s.conn.write(src) }
func (s *http1Stream_[C]) writeVec(srcVec *net.Buffers) (int64, error) {
	return s.conn.writeVec(srcVec)
}

// _http1In_ is a mixin.
type _http1In_ struct { // for backend1Response and server1Request
	// Parent
	*_httpIn_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *_http1In_) onUse(parent *_httpIn_) {
	r._httpIn_ = parent
}
func (r *_http1In_) onEnd() {
	r._httpIn_ = nil
}

func (r *_http1In_) growHead() bool { // HTTP/1 is not a binary protocol, we don't know how many bytes to grow, so just grow.
	// Is r.input full?
	if inputSize := int32(cap(r.input)); r.inputEdge == inputSize { // r.inputEdge reached end, so r.input is full
		if inputSize == _16K { // max r.input size is 16K, we cannot use a larger input anymore
			if r.receiving == httpSectionControl {
				r.headResult = StatusURITooLong
			} else { // httpSectionHeaders
				r.headResult = StatusRequestHeaderFieldsTooLarge
			}
			return false
		}
		// r.input size < 16K. We switch to a larger input (stock -> 4K -> 16K)
		stockSize := int32(cap(r.stockInput))
		var input []byte
		if inputSize == stockSize {
			input = Get4K()
		} else { // 4K
			input = Get16K()
		}
		copy(input, r.input) // copy all
		if inputSize != stockSize {
			PutNK(r.input)
		}
		r.input = input // a larger input is now used
	}
	// r.input is not full.
	if n, err := r.stream.read(r.input[r.inputEdge:]); err == nil {
		r.inputEdge += int32(n) // we might have only read 1 byte.
		return true
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		r.headResult = StatusRequestTimeout
	} else { // i/o error or unexpected EOF
		r.headResult = -1
	}
	return false
}
func (r *_http1In_) recvHeaderLines() bool { // *( field-name ":" OWS field-value OWS CRLF ) CRLF
	r.headerLines.from = uint8(len(r.primes))
	r.headerLines.edge = r.headerLines.from
	headerLine := &r.mainPair
	headerLine.zero()
	headerLine.kind = pairHeader
	headerLine.place = placeInput // all received header lines are in r.input
	// r.elemFore is at header section (if any) or end of header section (if none).
	for { // each header line
		// End of header section?
		if b := r.input[r.elemFore]; b == '\r' {
			// Skip '\r'
			if r.elemFore++; r.elemFore == r.inputEdge && !r.growHead() {
				return false
			}
			if r.input[r.elemFore] != '\n' {
				r.headResult, r.failReason = StatusBadRequest, "bad end of header section"
				return false
			}
			break
		} else if b == '\n' {
			break
		}

		// field-line = field-name ":" OWS field-value OWS

		// field-name = token
		// token = 1*tchar

		r.elemBack = r.elemFore // now r.elemBack is at field-line
		for {
			b := r.input[r.elemFore]
			if t := httpTchar[b]; t == 1 {
				// Fast path, do nothing
			} else if t == 2 { // A-Z
				b += 0x20 // to lower
				r.input[r.elemFore] = b
			} else if t == 3 { // '_'
				headerLine.setUnderscore()
			} else if b == ':' {
				break
			} else {
				r.headResult, r.failReason = StatusBadRequest, "header name contains bad character"
				return false
			}
			headerLine.nameHash += uint16(b)
			if r.elemFore++; r.elemFore == r.inputEdge && !r.growHead() {
				return false
			}
		}
		if nameSize := r.elemFore - r.elemBack; nameSize > 0 && nameSize <= 255 {
			headerLine.nameFrom, headerLine.nameSize = r.elemBack, uint8(nameSize)
		} else {
			r.headResult, r.failReason = StatusBadRequest, "header name out of range"
			return false
		}
		// Skip ':'
		if r.elemFore++; r.elemFore == r.inputEdge && !r.growHead() {
			return false
		}
		// Skip OWS before field-value (and OWS after field-value if it is empty)
		for r.input[r.elemFore] == ' ' || r.input[r.elemFore] == '\t' {
			if r.elemFore++; r.elemFore == r.inputEdge && !r.growHead() {
				return false
			}
		}
		// field-value   = *field-content
		// field-content = field-vchar [ 1*( %x20 / %x09 / field-vchar) field-vchar ]
		// field-vchar   = %x21-7E / %x80-FF
		// In other words, a string of octets is a field-value if and only if:
		// - it is *( %x21-7E / %x80-FF / %x20 / %x09)
		// - if it is not empty, it starts and ends with field-vchar
		r.elemBack = r.elemFore // now r.elemBack is at field-value (if not empty) or EOL (if field-value is empty)
		for {
			if b := r.input[r.elemFore]; (b >= 0x20 && b != 0x7F) || b == 0x09 {
				if r.elemFore++; r.elemFore == r.inputEdge && !r.growHead() {
					return false
				}
			} else if b == '\r' {
				// Skip '\r'
				if r.elemFore++; r.elemFore == r.inputEdge && !r.growHead() {
					return false
				}
				if r.input[r.elemFore] != '\n' {
					r.headResult, r.failReason = StatusBadRequest, "header value contains bad eol"
					return false
				}
				break
			} else if b == '\n' {
				break
			} else {
				r.headResult, r.failReason = StatusBadRequest, "header value contains bad character"
				return false
			}
		}
		// r.elemFore is at '\n'
		fore := r.elemFore
		if r.input[fore-1] == '\r' {
			fore--
		}
		if fore > r.elemBack { // field-value is not empty. now trim OWS after field-value
			for r.input[fore-1] == ' ' || r.input[fore-1] == '\t' {
				fore--
			}
		}
		headerLine.value.set(r.elemBack, fore)

		// Header line is received in general algorithm. Now add it
		if !r.addHeaderLine(headerLine) {
			// r.headResult is set.
			return false
		}

		// Header line is successfully received. Skip '\n'
		if r.elemFore++; r.elemFore == r.inputEdge && !r.growHead() {
			return false
		}
		// r.elemFore is now at the next header line or end of header section.
		headerLine.nameHash, headerLine.flags = 0, 0 // reset for next header line
	}
	r.receiving = httpSectionContent
	// Skip end of header section
	r.elemFore++
	// Now the head is received, and r.elemFore is at the beginning of content (if exists) or next message (if exists and is pipelined).
	r.head.set(0, r.elemFore)

	return true
}

func (r *_http1In_) readContent() (data []byte, err error) {
	if r.contentSize >= 0 { // sized
		return r._readSizedContent()
	} else { // vague. must be -2. -1 (no content) is excluded priorly
		return r._readVagueContent()
	}
}
func (r *_http1In_) _readSizedContent() ([]byte, error) {
	if r.receivedSize == r.contentSize { // content is entirely received
		if r.bodyWindow == nil { // body window is not used. this means content is immediate
			return r.contentText[:r.receivedSize], io.EOF
		} else { // r.bodyWindow was used.
			PutNK(r.bodyWindow)
			r.bodyWindow = nil
			return nil, io.EOF
		}
	}
	// Need more content text.
	if r.bodyWindow == nil {
		r.bodyWindow = Get16K() // will be freed on ends. must be >= 16K so r.imme can fit
	}
	if r.imme.notEmpty() {
		immeSize := copy(r.bodyWindow, r.input[r.imme.from:r.imme.edge]) // r.input is not larger than r.bodyWindow
		r.receivedSize = int64(immeSize)
		r.imme.zero()
		return r.bodyWindow[0:immeSize], nil
	}
	readSize := int64(cap(r.bodyWindow))
	if sizeLeft := r.contentSize - r.receivedSize; sizeLeft < readSize {
		readSize = sizeLeft
	}
	if r.bodyTime.IsZero() {
		r.bodyTime = time.Now()
	}
	if err := r.stream.setReadDeadline(); err != nil { // may be called multiple times during the reception of the sized content
		return nil, err
	}
	size, err := r.stream.readFull(r.bodyWindow[:readSize])
	if err == nil {
		if !r._isLongTime() {
			r.receivedSize += int64(size)
			return r.bodyWindow[:size], nil
		}
		err = httpInLongTime
	}
	return nil, err
}
func (r *_http1In_) _readVagueContent() ([]byte, error) {
	if r.bodyWindow == nil {
		r.bodyWindow = Get16K() // will be freed on ends. 16K is a tradeoff between performance and memory consumption, and can fit r.imme and trailer section
	}
	if r.imme.notEmpty() {
		r.chunkEdge = int32(copy(r.bodyWindow, r.input[r.imme.from:r.imme.edge])) // r.input is not larger than r.bodyWindow
		r.imme.zero()
	}
	if r.chunkEdge == 0 && !r.growChunked() { // r.bodyWindow is empty. must fill
		goto badRead
	}
	switch r.chunkSize { // size left in receiving current chunk
	case -2: // got chunk-data. needs CRLF or LF
		if r.bodyWindow[r.chunkFore] == '\r' {
			if r.chunkFore++; r.chunkFore == r.chunkEdge && !r.growChunked() {
				goto badRead
			}
		}
		fallthrough
	case -1: // got chunk-data CR. needs LF
		if r.bodyWindow[r.chunkFore] != '\n' {
			goto badRead
		}
		// Skip '\n'
		if r.chunkFore++; r.chunkFore == r.chunkEdge && !r.growChunked() {
			goto badRead
		}
		fallthrough
	case 0: // start a new chunk = chunk-size [chunk-ext] CRLF chunk-data CRLF
		r.chunkBack = r.chunkFore // now r.bodyWindow is used for receiving: chunk-size [chunk-ext] CRLF
		chunkSize := int64(0)
		for { // chunk-size = 1*HEXDIG
			b := r.bodyWindow[r.chunkFore]
			if b >= '0' && b <= '9' {
				b = b - '0'
			} else if b >= 'a' && b <= 'f' {
				b = b - 'a' + 10
			} else if b >= 'A' && b <= 'F' {
				b = b - 'A' + 10
			} else {
				break
			}
			chunkSize <<= 4
			chunkSize += int64(b)
			if r.chunkFore++; r.chunkFore-r.chunkBack >= 16 || (r.chunkFore == r.chunkEdge && !r.growChunked()) {
				goto badRead
			}
		}
		if chunkSize < 0 { // bad chunk size.
			goto badRead
		}
		if b := r.bodyWindow[r.chunkFore]; b == ';' { // ignore chunk-ext = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
			for r.bodyWindow[r.chunkFore] != '\n' {
				if r.chunkFore++; r.chunkFore == r.chunkEdge && !r.growChunked() {
					goto badRead
				}
			}
		} else if b == '\r' {
			// Skip '\r'
			if r.chunkFore++; r.chunkFore == r.chunkEdge && !r.growChunked() {
				goto badRead
			}
		}
		// Must be LF
		if r.bodyWindow[r.chunkFore] != '\n' {
			goto badRead
		}
		// Check target size
		if targetSize := r.receivedSize + chunkSize; targetSize >= 0 && targetSize <= r.maxContentSize {
			r.chunkSize = chunkSize
		} else { // invalid target size.
			// TODO: log error?
			goto badRead
		}
		// Skip '\n' at the end of: chunk-size [chunk-ext] CRLF
		if r.chunkFore++; r.chunkFore == r.chunkEdge && !r.growChunked() {
			goto badRead
		}
		// Last chunk?
		if r.chunkSize == 0 { // last-chunk = 1*("0") [chunk-ext] CRLF
			// last-chunk trailer-section CRLF
			if r.bodyWindow[r.chunkFore] == '\r' {
				// Skip '\r'
				if r.chunkFore++; r.chunkFore == r.chunkEdge && !r.growChunked() {
					goto badRead
				}
				if r.bodyWindow[r.chunkFore] != '\n' {
					goto badRead
				}
			} else if r.bodyWindow[r.chunkFore] != '\n' { // must be trailer-section = *( field-line CRLF)
				r.receiving = httpSectionTrailers
				if !r.recvTrailerLines() || !r.in.examineTail() {
					goto badRead
				}
				// r.recvTrailerLines() must ends with r.chunkFore being at the last '\n' after trailer-section.
			}
			// Skip the last '\n'
			r.chunkFore++ // now the whole vague content is received and r.chunkFore is immediately after the vague content.
			// Now we have found the end of current message, so determine r.inputNext and r.inputEdge.
			if r.chunkFore < r.chunkEdge { // still has data, stream is pipelined
				r.overChunked = true                                // so r.bodyWindow will be used as r.input on stream ends
				r.inputNext, r.inputEdge = r.chunkFore, r.chunkEdge // mark the next message
			} else { // no data anymore, stream is not pipelined
				r.inputNext, r.inputEdge = 0, 0 // reset input
				PutNK(r.bodyWindow)
				r.bodyWindow = nil
			}
			return nil, io.EOF
		}
		// Not last chunk, now r.chunkFore is at the beginning of: chunk-data CRLF
		fallthrough
	default: // r.chunkSize > 0, we are receiving: chunk-data CRLF
		r.chunkBack = 0 // so growChunked() works correctly
		var data span   // the chunk data we are receiving
		data.from = r.chunkFore
		if haveSize := int64(r.chunkEdge - r.chunkFore); haveSize <= r.chunkSize { // 1 <= haveSize <= r.chunkSize. chunk-data can be taken entirely
			r.receivedSize += haveSize
			data.edge = r.chunkEdge
			if haveSize == r.chunkSize { // exact chunk-data
				r.chunkSize = -2 // got chunk-data, needs CRLF or LF
			} else { // haveSize < r.chunkSize, not enough data.
				r.chunkSize -= haveSize
			}
			r.chunkFore, r.chunkEdge = 0, 0 // all data taken
		} else { // haveSize > r.chunkSize, more than chunk-data
			r.receivedSize += r.chunkSize
			data.edge = r.chunkFore + int32(r.chunkSize)
			if sizeLeft := r.chunkEdge - data.edge; sizeLeft == 1 { // chunk-data ?
				if b := r.bodyWindow[data.edge]; b == '\r' { // exact chunk-data CR
					r.chunkSize = -1 // got chunk-data CR, needs LF
				} else if b == '\n' { // exact chunk-data LF
					r.chunkSize = 0
				} else { // chunk-data X
					goto badRead
				}
				r.chunkFore, r.chunkEdge = 0, 0 // all data taken
			} else if r.bodyWindow[data.edge] == '\r' && r.bodyWindow[data.edge+1] == '\n' { // chunk-data CRLF..
				r.chunkSize = 0
				if sizeLeft == 2 { // exact chunk-data CRLF
					r.chunkFore, r.chunkEdge = 0, 0 // all data taken
				} else { // > 2, chunk-data CRLF X
					r.chunkFore = data.edge + 2
				}
			} else if r.bodyWindow[data.edge] == '\n' { // >=2, chunk-data LF X
				r.chunkSize = 0
				r.chunkFore = data.edge + 1
			} else { // >=2, chunk-data XX
				goto badRead
			}
		}
		return r.bodyWindow[data.from:data.edge], nil
	}
badRead:
	return nil, httpInBadChunk
}

func (r *_http1In_) recvTrailerLines() bool { // trailer-section = *( field-line CRLF)
	copy(r.bodyWindow, r.bodyWindow[r.chunkFore:r.chunkEdge]) // slide to start, we need a clean r.bodyWindow
	r.chunkEdge -= r.chunkFore
	r.chunkBack, r.chunkFore = 0, 0 // setting r.chunkBack = 0 means r.bodyWindow will not slide, so the whole trailer section must fit in r.bodyWindow.
	r.elemBack, r.elemFore = 0, 0   // for parsing trailer fields

	r.trailerLines.from = uint8(len(r.primes))
	r.trailerLines.edge = r.trailerLines.from
	trailerLine := &r.mainPair
	trailerLine.zero()
	trailerLine.kind = pairTrailer
	trailerLine.place = placeArray // all received trailer lines are placed in r.array
	for {
		if b := r.bodyWindow[r.elemFore]; b == '\r' {
			// Skip '\r'
			if r.elemFore++; r.elemFore == r.chunkEdge && !r.growChunked() {
				return false
			}
			if r.bodyWindow[r.elemFore] != '\n' {
				return false
			}
			break
		} else if b == '\n' {
			break
		}

		r.elemBack = r.elemFore // for field-name
		for {
			b := r.bodyWindow[r.elemFore]
			if t := httpTchar[b]; t == 1 {
				// Fast path, do nothing
			} else if t == 2 { // A-Z
				b += 0x20 // to lower
				r.bodyWindow[r.elemFore] = b
			} else if t == 3 { // '_'
				trailerLine.setUnderscore()
			} else if b == ':' {
				break
			} else {
				return false
			}
			trailerLine.nameHash += uint16(b)
			if r.elemFore++; r.elemFore == r.chunkEdge && !r.growChunked() {
				return false
			}
		}
		if nameSize := r.elemFore - r.elemBack; nameSize > 0 && nameSize <= 255 {
			trailerLine.nameFrom, trailerLine.nameSize = r.elemBack, uint8(nameSize)
		} else {
			return false
		}
		// Skip ':'
		if r.elemFore++; r.elemFore == r.chunkEdge && !r.growChunked() {
			return false
		}
		// Skip OWS before field-value (and OWS after field-value if it is empty)
		for r.bodyWindow[r.elemFore] == ' ' || r.bodyWindow[r.elemFore] == '\t' {
			if r.elemFore++; r.elemFore == r.chunkEdge && !r.growChunked() {
				return false
			}
		}
		r.elemBack = r.elemFore // for field-value or EOL
		for {
			if b := r.bodyWindow[r.elemFore]; (b >= 0x20 && b != 0x7F) || b == 0x09 {
				if r.elemFore++; r.elemFore == r.chunkEdge && !r.growChunked() {
					return false
				}
			} else if b == '\r' {
				// Skip '\r'
				if r.elemFore++; r.elemFore == r.chunkEdge && !r.growChunked() {
					return false
				}
				if r.bodyWindow[r.elemFore] != '\n' {
					return false
				}
				break
			} else if b == '\n' {
				break
			} else {
				return false
			}
		}
		// r.elemFore is at '\n'
		fore := r.elemFore
		if r.bodyWindow[fore-1] == '\r' {
			fore--
		}
		if fore > r.elemBack { // field-value is not empty. now trim OWS after field-value
			for r.bodyWindow[fore-1] == ' ' || r.bodyWindow[fore-1] == '\t' {
				fore--
			}
		}
		trailerLine.value.set(r.elemBack, fore)

		// Copy trailer line data to r.array
		fore = r.arrayEdge
		if !r.arrayCopy(trailerLine.nameAt(r.bodyWindow)) {
			return false
		}
		trailerLine.nameFrom = fore
		fore = r.arrayEdge
		if !r.arrayCopy(trailerLine.valueAt(r.bodyWindow)) {
			return false
		}
		trailerLine.value.set(fore, r.arrayEdge)

		// Trailer line is received in general algorithm. Now add it
		if !r.addTrailerLine(trailerLine) {
			return false
		}

		// Trailer line is successfully received. Skip '\n'
		if r.elemFore++; r.elemFore == r.chunkEdge && !r.growChunked() {
			return false
		}
		// r.elemFore is now at the next trailer line or end of trailer section.
		trailerLine.nameHash, trailerLine.flags = 0, 0 // reset for next trailer line
	}
	r.chunkFore = r.elemFore // r.chunkFore must ends at the last '\n'
	return true
}
func (r *_http1In_) growChunked() bool { // HTTP/1 is not a binary protocol, we don't know how many bytes to grow, so just grow.
	if r.chunkEdge == int32(cap(r.bodyWindow)) && r.chunkBack == 0 { // r.bodyWindow is full and we can't slide
		return false // element is too large
	}
	if r.chunkBack > 0 { // has previously used data, but now useless. slide to start so we can read more
		copy(r.bodyWindow, r.bodyWindow[r.chunkBack:r.chunkEdge])
		r.chunkEdge -= r.chunkBack
		r.chunkFore -= r.chunkBack
		r.chunkBack = 0
	}
	if r.bodyTime.IsZero() {
		r.bodyTime = time.Now()
	}
	err := r.stream.setReadDeadline() // may be called multiple times during the reception of the vague content
	if err == nil {
		n, e := r.stream.read(r.bodyWindow[r.chunkEdge:])
		r.chunkEdge += int32(n)
		if e == nil {
			if !r._isLongTime() {
				return true
			}
			e = httpInLongTime
		}
		err = e // including io.EOF which is unexpected here
	}
	// err != nil. TODO: log err
	return false
}

// _http1Out_ is a mixin.
type _http1Out_ struct { // for backend1Request and server1Response
	// Parent
	*_httpOut_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *_http1Out_) onUse(parent *_httpOut_) {
	r._httpOut_ = parent
}
func (r *_http1Out_) onEnd() {
	r._httpOut_ = nil
}

func (r *_http1Out_) addHeader(name []byte, value []byte) bool {
	if len(name) == 0 {
		return false
	}
	headerSize := len(name) + len(bytesColonSpace) + len(value) + len(bytesCRLF) // name: value\r\n
	if from, _, ok := r.growHeaders(headerSize); ok {
		from += copy(r.output[from:], name)
		r.output[from] = ':'
		r.output[from+1] = ' '
		from += 2
		from += copy(r.output[from:], value)
		r._addCRLFHeader(from)
		return true
	} else {
		return false
	}
}
func (r *_http1Out_) header(name []byte) (value []byte, ok bool) {
	if r.numHeaderFields > 1 && len(name) > 0 {
		from := uint16(0)
		for i := uint8(1); i < r.numHeaderFields; i++ {
			edge := r.edges[i]
			header := r.output[from:edge]
			if p := bytes.IndexByte(header, ':'); p != -1 && bytes.Equal(header[0:p], name) {
				return header[p+len(bytesColonSpace) : len(header)-len(bytesCRLF)], true
			}
			from = edge
		}
	}
	return
}
func (r *_http1Out_) hasHeader(name []byte) bool {
	if r.numHeaderFields > 1 && len(name) > 0 {
		from := uint16(0)
		for i := uint8(1); i < r.numHeaderFields; i++ {
			edge := r.edges[i]
			header := r.output[from:edge]
			if p := bytes.IndexByte(header, ':'); p != -1 && bytes.Equal(header[0:p], name) {
				return true
			}
			from = edge
		}
	}
	return false
}
func (r *_http1Out_) delHeader(name []byte) (deleted bool) {
	from := uint16(0)
	for i := uint8(1); i < r.numHeaderFields; {
		edge := r.edges[i]
		if p := bytes.IndexByte(r.output[from:edge], ':'); bytes.Equal(r.output[from:from+uint16(p)], name) {
			size := edge - from
			copy(r.output[from:], r.output[edge:])
			for j := i + 1; j < r.numHeaderFields; j++ {
				r.edges[j] -= size
			}
			r.outputEdge -= size
			r.numHeaderFields--
			deleted = true
		} else {
			from = edge
			i++
		}
	}
	return
}
func (r *_http1Out_) delHeaderAt(i uint8) {
	if i == 0 {
		BugExitln("delHeaderAt: i == 0 which must not happen")
	}
	from := r.edges[i-1]
	edge := r.edges[i]
	size := edge - from
	copy(r.output[from:], r.output[edge:])
	for j := i + 1; j < r.numHeaderFields; j++ {
		r.edges[j] -= size
	}
	r.outputEdge -= size
	r.numHeaderFields--
}
func (r *_http1Out_) _addCRLFHeader(from int) {
	r.output[from] = '\r'
	r.output[from+1] = '\n'
	r.edges[r.numHeaderFields] = uint16(from + 2)
	r.numHeaderFields++
}
func (r *_http1Out_) _addFixedHeader(name []byte, value []byte) { // used by finalizeHeaders
	r.outputEdge += uint16(copy(r.output[r.outputEdge:], name))
	r.output[r.outputEdge] = ':'
	r.output[r.outputEdge+1] = ' '
	r.outputEdge += 2
	r.outputEdge += uint16(copy(r.output[r.outputEdge:], value))
	r.output[r.outputEdge] = '\r'
	r.output[r.outputEdge+1] = '\n'
	r.outputEdge += 2
}

func (r *_http1Out_) sendChain() error { // TODO: if conn is TLS, don't use writeVec as it uses many Write() which might be slower than make+copy+write.
	return r._sendEntireChain()
	// TODO
	numRanges := len(r.contentRanges)
	if numRanges == 0 {
		return r._sendEntireChain()
	}
	// Partial content.
	if !r.asRequest { // as response
		r.out.(ServerResponse).SetStatus(StatusPartialContent)
	}
	if numRanges == 1 {
		return r._sendSingleRange()
	} else {
		return r._sendMultiRanges()
	}
}
func (r *_http1Out_) _sendEntireChain() error {
	r.out.finalizeHeaders()
	vector := r._prepareVector() // waiting to write
	if DebugLevel() >= 2 {
		if r.asRequest {
			Printf("[backend1Stream=%d]<=======[%s%s%s]\n", r.stream.ID(), vector[0], vector[1], vector[2])
		} else {
			Printf("[server1Stream=%d]------->[%s%s%s]\n", r.stream.ID(), vector[0], vector[1], vector[2])
		}
	}
	vectorFrom, vectorEdge := 0, 3
	for piece := r.chain.head; piece != nil; piece = piece.next {
		if piece.size == 0 {
			continue
		}
		if piece.IsText() { // plain text
			vector[vectorEdge] = piece.Text()
			vectorEdge++
		} else if piece.size <= _16K { // small file, <= 16K
			buffer := GetNK(piece.size) // 4K/16K
			if err := piece.copyTo(buffer); err != nil {
				r.stream.markBroken()
				PutNK(buffer)
				return err
			}
			vector[vectorEdge] = buffer[0:piece.size]
			vectorEdge++
			r.vector = vector[vectorFrom:vectorEdge]
			if err := r.writeVector(); err != nil {
				PutNK(buffer)
				return err
			}
			PutNK(buffer)
			vectorFrom, vectorEdge = 0, 0
		} else { // large file, > 16K
			if vectorFrom < vectorEdge {
				r.vector = vector[vectorFrom:vectorEdge]
				if err := r.writeVector(); err != nil { // texts
					return err
				}
				vectorFrom, vectorEdge = 0, 0
			}
			if err := r.writePiece(piece, false); err != nil { // the file
				return err
			}
		}
	}
	if vectorFrom < vectorEdge {
		r.vector = vector[vectorFrom:vectorEdge]
		return r.writeVector()
	}
	return nil
}
func (r *_http1Out_) _sendSingleRange() error {
	r.AddContentType(r.rangeType)
	valueBuffer := r.stream.buffer256()
	n := copy(valueBuffer, "bytes ")
	contentRange := r.contentRanges[0]
	n += i64ToDec(contentRange.From, valueBuffer[n:])
	valueBuffer[n] = '-'
	n++
	n += i64ToDec(contentRange.Last-1, valueBuffer[n:])
	valueBuffer[n] = '/'
	n++
	n += i64ToDec(r.contentSize, valueBuffer[n:])
	r.AddHeaderBytes(bytesContentRange, valueBuffer[:n])
	//return r._sendEntireChain()
	return nil
}
func (r *_http1Out_) _sendMultiRanges() error {
	valueBuffer := r.stream.buffer256()
	n := copy(valueBuffer, "multipart/byteranges; boundary=")
	n += copy(valueBuffer[n:], "xsd3lxT9b5c")
	r.AddHeaderBytes(bytesContentType, valueBuffer[:n])
	// TODO
	return nil
}
func (r *_http1Out_) _prepareVector() [][]byte {
	var vector [][]byte // waiting for write
	if r.forbidContent {
		vector = r.fixedVector[0:3]
		r.chain.free()
	} else if numPieces := r.chain.Qnty(); numPieces == 1 { // content chain has exactly one piece
		vector = r.fixedVector[0:4]
	} else { // numPieces >= 2
		vector = make([][]byte, 3+numPieces) // TODO(diogin): get from pool? defer pool.put()
	}
	vector[0] = r.out.controlData()
	vector[1] = r.out.addedHeaders()
	vector[2] = r.out.fixedHeaders()
	return vector
}

func (r *_http1Out_) echoChain(inChunked bool) error { // TODO: coalesce text pieces?
	for piece := r.chain.head; piece != nil; piece = piece.next {
		if err := r.writePiece(piece, inChunked); err != nil {
			return err
		}
	}
	return nil
}

func (r *_http1Out_) addTrailer(name []byte, value []byte) bool {
	if len(name) == 0 {
		return false
	}
	trailerSize := len(name) + len(bytesColonSpace) + len(value) + len(bytesCRLF) // name: value\r\n
	if from, _, ok := r.growTrailers(trailerSize); ok {
		from += copy(r.output[from:], name)
		r.output[from] = ':'
		r.output[from+1] = ' '
		from += 2
		from += copy(r.output[from:], value)
		r.output[from] = '\r'
		r.output[from+1] = '\n'
		r.edges[r.numTrailerFields] = uint16(from + 2)
		r.numTrailerFields++
		return true
	} else {
		return false
	}
}
func (r *_http1Out_) trailer(name []byte) (value []byte, ok bool) {
	if r.numTrailerFields > 1 && len(name) > 0 {
		from := uint16(0)
		for i := uint8(1); i < r.numTrailerFields; i++ {
			edge := r.edges[i]
			trailer := r.output[from:edge]
			if p := bytes.IndexByte(trailer, ':'); p != -1 && bytes.Equal(trailer[0:p], name) {
				return trailer[p+len(bytesColonSpace) : len(trailer)-len(bytesCRLF)], true
			}
			from = edge
		}
	}
	return
}
func (r *_http1Out_) trailers() []byte { return r.output[0:r.outputEdge] } // Header fields and trailer fields are not manipulated at the same time, so after header fields is sent, r.output is used by trailer fields.

func (r *_http1Out_) proxyPassBytes(data []byte) error { return r.writeBytes(data) }

func (r *_http1Out_) finalizeVague() error {
	if r.numTrailerFields == 1 { // no trailer section
		return r.writeBytes(http1BytesZeroCRLFCRLF) // 0\r\n\r\n
	} else { // with trailer section
		r.vector = r.fixedVector[0:3]
		r.vector[0] = http1BytesZeroCRLF // 0\r\n
		r.vector[1] = r.trailers()       // field-name: field-value\r\n
		r.vector[2] = bytesCRLF          // \r\n
		return r.writeVector()
	}
}

func (r *_http1Out_) writeHeaders() error { // used by echo and pass
	r.out.finalizeHeaders()
	r.vector = r.fixedVector[0:3]
	r.vector[0] = r.out.controlData()
	r.vector[1] = r.out.addedHeaders()
	r.vector[2] = r.out.fixedHeaders()
	if DebugLevel() >= 2 {
		if r.asRequest {
			Printf("[backend1Stream=%d]<=======", r.stream.ID(), r.vector[0], r.vector[1], r.vector[2])
		} else {
			Printf("[server1Stream=%d]------->[%s%s%s]", r.stream.ID(), r.vector[0], r.vector[1], r.vector[2])
		}
	}
	if err := r.writeVector(); err != nil {
		return err
	}
	r.outputEdge = 0 // now that header fields are all sent, r.output will be used by trailer fields (if any), so reset it.
	return nil
}
func (r *_http1Out_) writePiece(piece *Piece, inChunked bool) error {
	if r.stream.isBroken() {
		return httpOutWriteBroken
	}
	if piece.IsText() { // text piece
		return r._writeTextPiece(piece, inChunked)
	} else {
		return r._writeFilePiece(piece, inChunked)
	}
}
func (r *_http1Out_) _writeTextPiece(piece *Piece, inChunked bool) error {
	if inChunked { // HTTP/1.1 chunked data
		sizeBuffer := r.stream.buffer256() // enough for chunk size
		n := i64ToHex(piece.size, sizeBuffer)
		sizeBuffer[n] = '\r'
		sizeBuffer[n+1] = '\n'
		n += 2
		r.vector = r.fixedVector[0:3] // we reuse r.vector and r.fixedVector
		r.vector[0] = sizeBuffer[:n]
		r.vector[1] = piece.Text()
		r.vector[2] = bytesCRLF
		return r.writeVector()
	} else { // HTTP/1.0, or raw data
		return r.writeBytes(piece.Text())
	}
}
func (r *_http1Out_) _writeFilePiece(piece *Piece, inChunked bool) error {
	// file piece. currently we don't use the sendfile(2) syscall, maybe in the future we'll find a way to use it for better performance.
	buffer := Get16K() // 16K is a tradeoff between performance and memory consumption.
	defer PutNK(buffer)
	sizeRead := int64(0)
	for {
		if sizeRead == piece.size {
			return nil
		}
		readSize := int64(cap(buffer))
		if sizeLeft := piece.size - sizeRead; sizeLeft < readSize {
			readSize = sizeLeft
		}
		n, err := piece.file.ReadAt(buffer[:readSize], sizeRead)
		sizeRead += int64(n)
		if err != nil && sizeRead != piece.size {
			r.stream.markBroken()
			return err
		}
		if r.sendTime.IsZero() {
			r.sendTime = time.Now()
		}
		if err = r.stream.setWriteDeadline(); err != nil { // for _writeFilePiece
			r.stream.markBroken()
			return err
		}
		if inChunked { // use HTTP/1.1 chunked mode
			sizeBuffer := r.stream.buffer256() // enough for chunk size
			k := i64ToHex(int64(n), sizeBuffer)
			sizeBuffer[k] = '\r'
			sizeBuffer[k+1] = '\n'
			k += 2
			r.vector = r.fixedVector[0:3]
			r.vector[0] = sizeBuffer[:k]
			r.vector[1] = buffer[:n]
			r.vector[2] = bytesCRLF
			_, err = r.stream.writeVec(&r.vector)
		} else { // HTTP/1.0, or identity content
			_, err = r.stream.write(buffer[0:n])
		}
		if err = r._longTimeCheck(err); err != nil {
			return err
		}
	}
}
func (r *_http1Out_) writeVector() error {
	if r.stream.isBroken() {
		return httpOutWriteBroken
	}
	if len(r.vector) == 1 && len(r.vector[0]) == 0 { // empty data
		return nil
	}
	if r.sendTime.IsZero() {
		r.sendTime = time.Now()
	}
	if err := r.stream.setWriteDeadline(); err != nil { // for writeVector
		r.stream.markBroken()
		return err
	}
	_, err := r.stream.writeVec(&r.vector)
	return r._longTimeCheck(err)
}
func (r *_http1Out_) writeBytes(data []byte) error {
	if r.stream.isBroken() {
		return httpOutWriteBroken
	}
	if len(data) == 0 { // empty data
		return nil
	}
	if r.sendTime.IsZero() {
		r.sendTime = time.Now()
	}
	if err := r.stream.setWriteDeadline(); err != nil { // for writeBytes
		r.stream.markBroken()
		return err
	}
	_, err := r.stream.write(data)
	return r._longTimeCheck(err)
}

// _http1Socket_ is a mixin.
type _http1Socket_ struct { // for backend1Socket and server1Socket
	// Parent
	*_httpSocket_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (s *_http1Socket_) onUse(parent *_httpSocket_) {
	s._httpSocket_ = parent
}
func (s *_http1Socket_) onEnd() {
	s._httpSocket_ = nil
}

func (s *_http1Socket_) todo1() {
	s.todo()
}

////////////////////////////////////////////////////////////////////////////////

// server1Conn is the server-side HTTP/1 connection.
type server1Conn struct {
	// Parent
	http1Conn_[*httpxGate, *server1Stream]
	// Mixins
	// Assocs
	stream server1Stream // an http/1 connection has exactly one stream
	// Conn states (stocks)
	// Conn states (controlled)
	// Conn states (non-zeros)
	closeSafe bool // if false, then send a FIN first to avoid TCP's RST following immediate close(). true by default
	// Conn states (zeros)
}

var poolServer1Conn sync.Pool

func getServer1Conn(id int64, gate *httpxGate, netConn net.Conn, rawConn syscall.RawConn) *server1Conn {
	var servConn *server1Conn
	if x := poolServer1Conn.Get(); x == nil {
		servConn = new(server1Conn)
		servStream := &servConn.stream
		servReq, servResp := &servStream.request, &servStream.response
		servReq.stream = servStream
		servReq.in = servReq
		servResp.stream = servStream
		servResp.out = servResp
		servResp.request = servReq
	} else {
		servConn = x.(*server1Conn)
	}
	servConn.onGet(id, gate, netConn, rawConn)
	return servConn
}
func putServer1Conn(servConn *server1Conn) {
	servConn.onPut()
	poolServer1Conn.Put(servConn)
}

func (c *server1Conn) onGet(id int64, gate *httpxGate, netConn net.Conn, rawConn syscall.RawConn) {
	c.http1Conn_.onGet(id, gate, netConn, rawConn)

	c.closeSafe = true

	// Input is conn scoped but put in stream scoped request for convenience
	servReq := &c.stream.request
	servReq.input = servReq.stockInput[:]
}
func (c *server1Conn) onPut() {
	// Input, inputNext, and inputEdge are conn scoped but put in stream scoped request for convenience
	servReq := &c.stream.request
	if cap(servReq.input) != cap(servReq.stockInput) { // fetched from pool
		PutNK(servReq.input)
		servReq.input = nil
	}
	servReq.inputNext, servReq.inputEdge = 0, 0

	c.http1Conn_.onPut()
}

func (c *server1Conn) serve() { // runner
	stream := &c.stream
	for c.persistent { // each queued stream
		stream.onUse(c, c.nextStreamID())
		stream.execute()
		stream.onEnd()
	}

	// RFC 9112 (section 9.6):
	// If a server performs an immediate close of a TCP connection, there is
	// a significant risk that the client will not be able to read the last
	// HTTP response. If the server receives additional data from the
	// client on a fully closed connection, such as another request sent by
	// the client before receiving the server's response, the server's TCP
	// stack will send a reset packet to the client; unfortunately, the
	// reset packet might erase the client's unacknowledged input buffers
	// before they can be read and interpreted by the client's HTTP parser.

	// To avoid the TCP reset problem, servers typically close a connection
	// in stages. First, the server performs a half-close by closing only
	// the write side of the read/write connection. The server then
	// continues to read from the connection until it receives a
	// corresponding close by the client, or until the server is reasonably
	// certain that its own TCP stack has received the client's
	// acknowledgement of the packet(s) containing the server's last
	// response. Finally, the server fully closes the connection.
	netConn := c.netConn
	if !c.closeSafe {
		if c.UDSMode() {
			netConn.(*net.UnixConn).CloseWrite()
		} else if c.TLSMode() {
			netConn.(*tls.Conn).CloseWrite()
		} else {
			netConn.(*net.TCPConn).CloseWrite()
		}
		time.Sleep(time.Second)
	}
	netConn.Close()

	c.holder.DecConcurrentConns()
	c.holder.DecConn()
	putServer1Conn(c)
}

// server1Stream is the server-side HTTP/1 stream.
type server1Stream struct {
	// Parent
	http1Stream_[*server1Conn]
	// Mixins
	// Assocs
	request  server1Request  // the server-side http/1 request
	response server1Response // the server-side http/1 response
	socket   *server1Socket  // the server-side http/1 webSocket
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (s *server1Stream) onUse(conn *server1Conn, id int64) { // for non-zeros
	s.http1Stream_.onUse(conn, id)

	s.request.onUse()
	s.response.onUse()
}
func (s *server1Stream) onEnd() { // for zeros
	s.response.onEnd()
	s.request.onEnd()
	if s.socket != nil {
		s.socket.onEnd()
		s.socket = nil
	}

	s.http1Stream_.onEnd()
}

func (s *server1Stream) execute() {
	req, resp := &s.request, &s.response

	req.recvHead()

	if req.HeadResult() != StatusOK { // receiving request error
		s._serveAbnormal(req, resp)
		return
	}

	if req.IsCONNECT() {
		req.headResult, req.failReason = StatusNotImplemented, "http tunnel proxy is not implemented here"
		s._serveAbnormal(req, resp)
		return
	}

	conn := s.conn
	server := conn.holder.server

	// RFC 9112 (section 3.3):
	// If the server's configuration provides for a fixed URI scheme, or a
	// scheme is provided by a trusted outbound gateway, that scheme is
	// used for the target URI. This is common in large-scale deployments
	// because a gateway server will receive the client's connection context
	// and replace that with their own connection to the inbound server.
	// Otherwise, if the request is received over a secured connection, the
	// target URI's scheme is "https"; if not, the scheme is "http".
	if server.forceScheme != -1 { // forceScheme is set explicitly
		req.schemeCode = uint8(server.forceScheme)
	} else if server.alignScheme { // scheme is not forced. should it be aligned?
		if conn.TLSMode() { // secured
			if req.schemeCode == SchemeHTTP {
				req.schemeCode = SchemeHTTPS
			}
		} else { // not secured
			if req.schemeCode == SchemeHTTPS {
				req.schemeCode = SchemeHTTP
			}
		}
	}

	webapp := server.findWebapp(req.RiskyHostname())

	if webapp == nil {
		req.headResult, req.failReason = StatusNotFound, "target webapp is not found in this server"
		s._serveAbnormal(req, resp)
		return
	}
	if !webapp.isDefault && !bytes.Equal(req.RiskyColonport(), server.ColonportBytes()) {
		req.headResult, req.failReason = StatusNotFound, "authoritative webapp is not found in this server"
		s._serveAbnormal(req, resp)
		return
	}

	req.webapp = webapp
	resp.webapp = webapp

	if !req.upgradeSocket { // exchan mode
		if req.contentIsForm() {
			if req.formKind == httpFormMultipart { // we allow a larger content size for uploading through multipart/form-data (because large files are written to disk).
				req.maxContentSize = webapp.maxMultiformSize
			} else { // application/x-www-form-urlencoded is limited in a smaller size because it will be loaded into memory
				req.maxContentSize = int64(req.maxMemoryContentSize)
			}
		}
		if req.contentSize > req.maxContentSize {
			if req.expectContinue {
				req.headResult = StatusExpectationFailed
			} else {
				req.headResult, req.failReason = StatusContentTooLarge, "content size exceeds webapp's limit"
			}
			s._serveAbnormal(req, resp)
			return
		}

		// Prepare the response according to the request
		if req.IsHEAD() {
			resp.forbidContent = true
		}

		if req.expectContinue && !s._writeContinue() {
			return
		}
		conn.cumulativeStreams.Add(1)
		if maxCumulativeStreams := server.maxCumulativeStreamsPerConn; (maxCumulativeStreams > 0 && conn.cumulativeStreams.Load() == maxCumulativeStreams) || !req.KeepAlive() || conn.holder.IsShut() {
			conn.persistent = false // reaches limit, or client told us to close, or gate was shut
		}

		s.executeExchan(webapp, req, resp)

		if s.isBroken() {
			conn.persistent = false // i/o error, close anyway
		}
	} else { // socket mode.
		if req.expectContinue && !s._writeContinue() {
			return
		}

		s.executeSocket()

		conn.persistent = false // explicitly close for webSocket
	}
}
func (s *server1Stream) _serveAbnormal(req *server1Request, resp *server1Response) { // 4xx & 5xx
	if DebugLevel() >= 2 {
		Printf("server=%s gate=%d conn=%d headResult=%d\n", s.conn.holder.server.CompName(), s.conn.holder.ID(), s.conn.id, s.request.headResult)
	}
	s.conn.persistent = false // we are in abnormal state, so close anyway

	status := req.headResult
	if status == -1 || (status == StatusRequestTimeout && !req.gotSomeInput) {
		return // send nothing.
	}
	// So we need to send something...
	if status == StatusContentTooLarge || status == StatusURITooLong || status == StatusRequestHeaderFieldsTooLarge {
		// The receiving side may has data when we close the connection
		s.conn.closeSafe = false
	}
	var content []byte
	if errorPage, ok := serverErrorPages[status]; !ok {
		content = http1Controls[status]
	} else if req.failReason == "" {
		content = errorPage
	} else {
		content = ConstBytes(req.failReason)
	}
	// Use response as a dumb struct here, don't use its methods (like Send) to send anything as we are in abnormal state!
	resp.status = status
	resp.AddHeaderBytes(bytesContentType, bytesTypeHTML)
	resp.contentSize = int64(len(content))
	if status == StatusMethodNotAllowed {
		// Currently only WebSocket use this status in abnormal state, so GET is hard coded.
		resp.AddHeaderBytes(bytesAllow, bytesGET)
	}
	resp.finalizeHeaders()
	if req.IsHEAD() || resp.forbidContent { // we follow the method semantic even we are in abnormal
		resp.vector = resp.fixedVector[0:3]
	} else {
		resp.vector = resp.fixedVector[0:4]
		resp.vector[3] = content
	}
	resp.vector[0] = resp.controlData()
	resp.vector[1] = resp.addedHeaders()
	resp.vector[2] = resp.fixedHeaders()
	if s.setWriteDeadline() == nil { // for _serveAbnormal
		// Ignore any error, as the connection will be closed anyway.
		s.writeVec(&resp.vector)
	}
}
func (s *server1Stream) _writeContinue() bool { // 100 continue
	// This is an interim response, so write directly.
	if s.setWriteDeadline() == nil { // for _writeContinue
		if _, err := s.write(http1BytesContinue); err == nil {
			return true
		}
	}
	s.conn.persistent = false // i/o error, close anyway
	return false
}

func (s *server1Stream) executeExchan(webapp *Webapp, req *server1Request, resp *server1Response) { // request & response
	webapp.dispatchExchan(req, resp)

	if !resp.isSent { // only happens for sized contents because for vague contents the response must be sent on echo()
		resp.sendChain()
	} else if resp.isVague() { // for vague contents, we end vague content and write trailer fields (if exist) here
		resp.endVague()
	}

	if !req.contentReceived { // request content exists but was not used, we receive and drop it here
		req._dropContent()
	}
}
func (s *server1Stream) executeSocket() { // upgrade: websocket. See RFC 6455
	// TODO(diogin): implementation.
	// NOTICE: use idle timeout or clear read timeout otherwise?
	s.write([]byte("HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n"))
}

// server1Request is the server-side HTTP/1 request.
type server1Request struct { // incoming. needs parsing
	// Parent
	serverRequest_
	// Assocs
	in1 _http1In_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *server1Request) onUse() {
	r.serverRequest_.onUse(Version1_1)
	r.in1.onUse(&r._httpIn_)
}
func (r *server1Request) onEnd() {
	r.serverRequest_.onEnd()
	r.in1.onEnd()
}

func (r *server1Request) recvHead() { // control data + header section
	if err := r.stream.setReadDeadline(); err != nil { // the entire request head must be received in one read timeout
		r.headResult = -1
		return
	}
	if r.inputEdge == 0 && !r.in1.growHead() { // r.inputEdge == 0 means r.input is empty, so we must fill it
		// r.headResult is set.
		return
	}
	if !r._recvControlData() || !r.in1.recvHeaderLines() || !r.examineHead() {
		// r.headResult is set.
		return
	}
	r.tidyInput()
	if DebugLevel() >= 2 {
		Printf("[server1Stream=%d]<-------[%s]\n", r.stream.ID(), r.input[r.head.from:r.head.edge])
	}
}
func (r *server1Request) _recvControlData() bool { // request-line = method SP request-target SP HTTP-version CRLF
	r.elemBack, r.elemFore = 0, 0

	// method = token
	// token = 1*tchar
	methodHash := uint16(0)
	for {
		if b := r.input[r.elemFore]; httpTchar[b] != 0 {
			methodHash += uint16(b)
			if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
				return false
			}
		} else if b == ' ' {
			break
		} else {
			r.headResult, r.failReason = StatusBadRequest, "invalid character in method"
			return false
		}
	}
	if r.elemBack == r.elemFore {
		r.headResult, r.failReason = StatusBadRequest, "empty method"
		return false
	}
	r.gotSomeInput = true
	r.method.set(r.elemBack, r.elemFore)
	r.recognizeMethod(r.input[r.elemBack:r.elemFore], methodHash)
	// Skip SP after method
	if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
		return false
	}

	// Now r.elemFore is at request-target.
	r.elemBack = r.elemFore
	// request-target = absolute-form / origin-form / authority-form / asterisk-form
	if b := r.input[r.elemFore]; b != '*' && !r.IsCONNECT() { // absolute-form / origin-form
		if b != '/' { // absolute-form
			// absolute-form = absolute-URI
			// absolute-URI = scheme ":" hier-part [ "?" query ]
			// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
			// hier-part = "//" authority path-abempty
			// authority = host [ ":" port ]
			// path-abempty = *( "/" segment)

			// Scheme
			for {
				if b := r.input[r.elemFore]; b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '-' || b == '.' {
					// Do nothing
				} else if b >= 'A' && b <= 'Z' {
					// RFC 9110 (section 4.2.3):
					// The scheme and host are case-insensitive and normally provided in lowercase;
					// all other components are compared in a case-sensitive manner.
					r.input[r.elemFore] = b + 0x20 // to lower
				} else if b == ':' {
					break
				} else {
					r.headResult, r.failReason = StatusBadRequest, "bad scheme"
					return false
				}
				if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
					return false
				}
			}
			if scheme := r.input[r.elemBack:r.elemFore]; bytes.Equal(scheme, bytesHTTP) {
				r.schemeCode = SchemeHTTP
			} else if bytes.Equal(scheme, bytesHTTPS) {
				r.schemeCode = SchemeHTTPS
			} else {
				r.headResult, r.failReason = StatusBadRequest, "unknown scheme"
				return false
			}
			// Skip ':'
			if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
				return false
			}
			if r.input[r.elemFore] != '/' {
				r.headResult, r.failReason = StatusBadRequest, "bad first slash"
				return false
			}
			// Skip '/'
			if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
				return false
			}
			if r.input[r.elemFore] != '/' {
				r.headResult, r.failReason = StatusBadRequest, "bad second slash"
				return false
			}
			// Skip '/'
			if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
				return false
			}
			// authority = host [ ":" port ]
			// host = IP-literal / IPv4address / reg-name
			r.elemBack = r.elemFore
			for {
				if b = r.input[r.elemFore]; b >= 'A' && b <= 'Z' {
					r.input[r.elemFore] = b + 0x20 // to lower
				} else if b == '/' || b == ' ' {
					break
				}
				if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
					return false
				}
			}
			if r.elemBack == r.elemFore {
				r.headResult, r.failReason = StatusBadRequest, "empty authority is not allowed"
				return false
			}
			if !r.parseAuthority(r.elemBack, r.elemFore, true) { // save = true
				r.headResult, r.failReason = StatusBadRequest, "bad authority"
				return false
			}
			if b == ' ' { // end of request-target. don't treat this as asterisk-form! r.uri is empty but we fetch it through r.URI() or like which gives '/' if uri is empty
				if r.IsOPTIONS() { // OPTIONS http://www.example.org:8001 HTTP/1.1
					r.asteriskOptions = true
				} else { // GET http://www.example.org HTTP/1.1
					// Do nothing.
				}
				goto beforeVersion // request target is done, since origin-form always starts with '/', while b is ' ' here.
			}
			r.elemBack = r.elemFore // at '/'.
		}
		// RFC 9112 (3.2.1)
		//
		// The most common form of request-target is the origin-form.
		//
		//   origin-form = absolute-path [ "?" query ]
		//       absolute-path = 1*( "/" segment )
		//           segment = *pchar
		//       query = *( pchar / "/" / "?" )
		//
		// When making a request directly to an origin server, other than a
		// CONNECT or server-wide OPTIONS request (as detailed below), a client
		// MUST send only the absolute path and query components of the target
		// URI as the request-target. If the target URI's path component is
		// empty, the client MUST send "/" as the path within the origin-form of
		// request-target. A Host header field is also sent, as defined in
		// Section 7.2 of [HTTP].
		var (
			state = 1   // in path
			octet byte  // byte value of %xx
			qsOff int32 // offset of query string, if exists
		)
		query := &r.mainPair
		query.zero()
		query.kind = pairQuery
		query.place = placeArray // all received queries are placed in r.array because queries are decoded

		// r.elemFore is at '/'.
	uri:
		for { // TODO: use a better algorithm to improve performance, state machine might be slow here.
			b := r.input[r.elemFore]
			switch state {
			case 1: // in path
				if httpPchar[b] == 1 { // excluding '?'
					r.arrayPush(b)
				} else if b == '%' {
					state = 0x1f // '1' means from state 1, 'f' means first HEXDIG
				} else if b == '?' {
					// Path is over, switch to query string parsing
					r.path = r.array[0:r.arrayEdge]
					r.queries.from = uint8(len(r.primes))
					r.queries.edge = r.queries.from
					query.nameFrom = r.arrayEdge
					qsOff = r.elemFore - r.elemBack
					state = 2
				} else if b == ' ' { // end of request-target
					break uri
				} else {
					r.headResult, r.failReason = StatusBadRequest, "invalid path"
					return false
				}
			case 2: // in query string and expecting '=' to get a name
				if b == '=' {
					if nameSize := r.arrayEdge - query.nameFrom; nameSize <= 255 {
						query.nameSize = uint8(nameSize)
						query.value.from = r.arrayEdge
					} else {
						r.headResult, r.failReason = StatusBadRequest, "query name too long"
						return false
					}
					state = 3
				} else if httpPchar[b] > 0 { // including '?'
					if b == '+' {
						b = ' ' // application/x-www-form-urlencoded encodes ' ' as '+'
					}
					query.nameHash += uint16(b)
					r.arrayPush(b)
				} else if b == '%' {
					state = 0x2f // '2' means from state 2, 'f' means first HEXDIG
				} else if b == ' ' { // end of request-target
					break uri
				} else {
					r.headResult, r.failReason = StatusBadRequest, "invalid query name"
					return false
				}
			case 3: // in query string and expecting '&' to get a value
				if b == '&' {
					query.value.edge = r.arrayEdge
					if query.nameSize > 0 && !r.addQuery(query) {
						return false
					}
					query.nameHash = 0 // reset for next query
					query.nameFrom = r.arrayEdge
					state = 2
				} else if httpPchar[b] > 0 { // including '?'
					if b == '+' {
						b = ' ' // application/x-www-form-urlencoded encodes ' ' as '+'
					}
					r.arrayPush(b)
				} else if b == '%' {
					state = 0x3f // '3' means from state 3, 'f' means first HEXDIG
				} else if b == ' ' { // end of request-target
					break uri
				} else {
					r.headResult, r.failReason = StatusBadRequest, "invalid query value"
					return false
				}
			default: // in query string and expecting HEXDIG
				if b == ' ' { // end of request-target
					break uri
				}
				nybble, ok := byteFromHex(b)
				if !ok {
					r.headResult, r.failReason = StatusBadRequest, "invalid pct encoding"
					return false
				}
				if state&0xf == 0xf { // Expecting the first HEXDIG
					octet = nybble << 4
					state &= 0xf0 // this reserves last state and leads to the state of second HEXDIG
				} else { // Expecting the second HEXDIG
					octet |= nybble
					if state == 0x20 { // in name, calculate name hash
						query.nameHash += uint16(octet)
					} else if octet == 0x00 && state == 0x10 { // For security reasons, we reject "\x00" in path.
						r.headResult, r.failReason = StatusBadRequest, "malformed path"
						return false
					}
					r.arrayPush(octet)
					state >>= 4 // restore previous state
				}
			}
			if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
				return false
			}
		}
		if state == 1 { // path ends without a '?'
			r.path = r.array[0:r.arrayEdge]
		} else if state == 2 { // in query string and no '=' found
			r.queryString.set(r.elemBack+qsOff, r.elemFore)
			// Since there is no '=', we ignore this query
		} else if state == 3 { // in query string and no '&' found
			r.queryString.set(r.elemBack+qsOff, r.elemFore)
			query.value.edge = r.arrayEdge
			if query.nameSize > 0 && !r.addQuery(query) {
				return false
			}
		} else { // incomplete pct-encoded
			r.headResult, r.failReason = StatusBadRequest, "incomplete pct-encoded"
			return false
		}

		r.uri.set(r.elemBack, r.elemFore)
		if qsOff == 0 {
			r.encodedPath = r.uri
		} else {
			r.encodedPath.set(r.elemBack, r.elemBack+qsOff)
		}
		r.cleanPath()
	} else if b == '*' { // OPTIONS *, asterisk-form
		// RFC 9112 (section 3.2.4):
		// The "asterisk-form" of request-target is only used for a server-wide OPTIONS request (Section 9.3.7 of [HTTP]).
		if !r.IsOPTIONS() {
			r.headResult, r.failReason = StatusBadRequest, "asterisk-form is only used by OPTIONS method"
			return false
		}
		// Skip '*'. We don't use it as uri! Instead, we use '/'. To test OPTIONS *, test r.asteriskOptions set below.
		if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
			return false
		}
		r.asteriskOptions = true
		// Expect SP
		if r.input[r.elemFore] != ' ' {
			r.headResult, r.failReason = StatusBadRequest, "malformed asterisk-form"
			return false
		}
		// RFC 9112 (section 3.3):
		// If the request-target is in authority-form or asterisk-form, the
		// target URI's combined path and query component is empty. Otherwise,
		// the target URI's combined path and query component is the request-target.
	} else { // CONNECT method, must be authority-form
		// RFC 9112 (section 3.2.3):
		// The "authority-form" of request-target is only used for CONNECT requests (Section 9.3.6 of [HTTP]).
		//
		//   authority-form = uri-host ":" port
		//
		// When making a CONNECT request to establish a tunnel through one or more proxies,
		// a client MUST send only the host and port of the tunnel destination as the request-target.
		for {
			if b := r.input[r.elemFore]; b >= 'A' && b <= 'Z' {
				r.input[r.elemFore] = b + 0x20 // to lower
			} else if b == ' ' {
				break
			}
			if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
				return false
			}
		}
		if r.elemBack == r.elemFore {
			r.headResult, r.failReason = StatusBadRequest, "empty authority is not allowed"
			return false
		}
		if !r.parseAuthority(r.elemBack, r.elemFore, true) { // save = true
			r.headResult, r.failReason = StatusBadRequest, "invalid authority"
			return false
		}
		// RFC 9112 (section 3.3):
		// If the request-target is in authority-form or asterisk-form, the
		// target URI's combined path and query component is empty. Otherwise,
		// the target URI's combined path and query component is the request-target.
	}

beforeVersion: // r.elemFore is at ' '.
	// Skip SP before HTTP-version
	if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
		return false
	}

	// Now r.elemFore is at HTTP-version.
	r.elemBack = r.elemFore
	// HTTP-version = HTTP-name "/" DIGIT "." DIGIT
	// HTTP-name = %x48.54.54.50 ; "HTTP", case-sensitive
	if have := r.inputEdge - r.elemFore; have >= 9 {
		// r.elemFore -> EOL
		// r.inputEdge -> after EOL or more
		r.elemFore += 8
	} else { // have < 9, but len("HTTP/1.X\n") = 9.
		// r.elemFore at 'H' -> EOL
		// r.inputEdge at "TTP/1.X\n" -> after EOL
		r.elemFore = r.inputEdge - 1
		for i, n := int32(0), 9-have; i < n; i++ {
			if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
				return false
			}
		}
	}
	if version := r.input[r.elemBack:r.elemFore]; bytes.Equal(version, bytesHTTP1_1) {
		r.httpVersion = Version1_1
	} else if bytes.Equal(version, bytesHTTP1_0) {
		r.httpVersion = Version1_0
	} else { // i don't believe there will be an HTTP/1.2 in the future.
		r.headResult = StatusHTTPVersionNotSupported
		return false
	}
	if r.input[r.elemFore] == '\r' {
		if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
			return false
		}
	}
	if r.input[r.elemFore] != '\n' {
		r.headResult, r.failReason = StatusBadRequest, "bad eol of start line"
		return false
	}
	r.receiving = httpSectionHeaders
	// Skip '\n'
	if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
		return false
	}

	return true
}
func (r *server1Request) tidyInput() {
	// r.elemFore is at the beginning of content (if exists) or next request (if exists and is pipelined).
	if r.contentSize == -1 { // no content
		r.contentReceived = true      // we treat it as "received"
		r.formReceived = true         // set anyway
		if r.elemFore < r.inputEdge { // still has data, stream is pipelined
			r.inputNext = r.elemFore // mark the beginning of the next request
		} else { // r.elemFore == r.inputEdge, no data anymore
			r.inputNext, r.inputEdge = 0, 0 // reset
		}
		return
	}
	// content exists (sized or vague)
	r.imme.set(r.elemFore, r.inputEdge)
	if r.contentSize >= 0 { // sized mode
		immeSize := int64(r.imme.size())
		if immeSize == 0 || immeSize <= r.contentSize {
			r.inputNext, r.inputEdge = 0, 0 // reset
		}
		if immeSize >= r.contentSize {
			r.contentReceived = true
			edge := r.elemFore + int32(r.contentSize)
			if immeSize > r.contentSize { // still has data, streams are pipelined
				r.imme.set(r.elemFore, edge)
				r.inputNext = edge // mark the beginning of next request
			}
			r.receivedSize = r.contentSize           // content is received entirely.
			r.contentText = r.input[r.elemFore:edge] // exact.
			r.contentTextKind = httpContentTextInput
		}
		if r.contentSize == 0 {
			r.formReceived = true // no content means no form, so mark it as "received"
		}
	} else { // vague mode
		// We don't know the size of vague content. Let chunked receivers to decide & clean r.input.
	}
}

func (r *server1Request) readContent() (data []byte, err error) { return r.in1.readContent() }

// server1Response is the server-side HTTP/1 response.
type server1Response struct { // outgoing. needs building
	// Parent
	serverResponse_
	// Assocs
	out1 _http1Out_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *server1Response) onUse() {
	r.serverResponse_.onUse(Version1_1)
	r.out1.onUse(&r._httpOut_)
}
func (r *server1Response) onEnd() {
	r.serverResponse_.onEnd()
	r.out1.onEnd()
}

func (r *server1Response) controlData() []byte { // overrides r.serverResponse_.controlData()
	var start []byte
	if r.status < int16(len(http1Controls)) && http1Controls[r.status] != nil {
		start = http1Controls[r.status]
	} else {
		r.start = http1Status
		r.start[9] = byte(r.status/100 + '0')
		r.start[10] = byte(r.status/10%10 + '0')
		r.start[11] = byte(r.status%10 + '0')
		start = r.start[:]
	}
	return start
}

func (r *server1Response) addHeader(name []byte, value []byte) bool {
	return r.out1.addHeader(name, value)
}
func (r *server1Response) header(name []byte) (value []byte, ok bool) { return r.out1.header(name) }
func (r *server1Response) hasHeader(name []byte) bool                 { return r.out1.hasHeader(name) }
func (r *server1Response) delHeader(name []byte) (deleted bool)       { return r.out1.delHeader(name) }
func (r *server1Response) delHeaderAt(i uint8)                        { r.out1.delHeaderAt(i) }

func (r *server1Response) AddHTTPSRedirection(authority string) bool {
	headerSize := len(http1BytesLocationHTTPS)
	if authority == "" {
		headerSize += len(r.request.RiskyAuthority())
	} else {
		headerSize += len(authority)
	}
	headerSize += len(r.request.RiskyURI()) + len(bytesCRLF)
	if from, _, ok := r.growHeaders(headerSize); ok {
		from += copy(r.output[from:], http1BytesLocationHTTPS)
		if authority == "" {
			from += copy(r.output[from:], r.request.RiskyAuthority())
		} else {
			from += copy(r.output[from:], authority)
		}
		from += copy(r.output[from:], r.request.RiskyURI())
		r.out1._addCRLFHeader(from)
		return true
	} else {
		return false
	}
}
func (r *server1Response) AddHostnameRedirection(hostname string) bool {
	var prefix []byte
	if r.request.IsHTTPS() {
		prefix = http1BytesLocationHTTPS
	} else {
		prefix = http1BytesLocationHTTP
	}
	headerSize := len(prefix)
	// TODO: remove colonport if colonport is default?
	colonport := r.request.RiskyColonport()
	headerSize += len(hostname) + len(colonport) + len(r.request.RiskyURI()) + len(bytesCRLF)
	if from, _, ok := r.growHeaders(headerSize); ok {
		from += copy(r.output[from:], prefix)
		from += copy(r.output[from:], hostname) // this is almost always configured, not client provided
		from += copy(r.output[from:], colonport)
		from += copy(r.output[from:], r.request.RiskyURI()) // original uri, won't split the response
		r.out1._addCRLFHeader(from)
		return true
	} else {
		return false
	}
}
func (r *server1Response) AddDirectoryRedirection() bool {
	var prefix []byte
	if r.request.IsHTTPS() {
		prefix = http1BytesLocationHTTPS
	} else {
		prefix = http1BytesLocationHTTP
	}
	req := r.request
	headerSize := len(prefix)
	headerSize += len(req.RiskyAuthority()) + len(req.RiskyURI()) + 1 + len(bytesCRLF)
	if from, _, ok := r.growHeaders(headerSize); ok {
		from += copy(r.output[from:], prefix)
		from += copy(r.output[from:], req.RiskyAuthority())
		from += copy(r.output[from:], req.RiskyEncodedPath())
		r.output[from] = '/'
		from++
		if len(req.RiskyQueryString()) > 0 {
			from += copy(r.output[from:], req.RiskyQueryString())
		}
		r.out1._addCRLFHeader(from)
		return true
	} else {
		return false
	}
}

func (r *server1Response) AddCookie(cookie *Cookie) bool {
	if cookie.name == "" || cookie.invalid {
		return false
	}
	headerSize := len(bytesSetCookie) + len(bytesColonSpace) + cookie.size() + len(bytesCRLF) // set-cookie: cookie\r\n
	if from, _, ok := r.growHeaders(headerSize); ok {
		from += copy(r.output[from:], bytesSetCookie)
		r.output[from] = ':'
		r.output[from+1] = ' '
		from += 2
		from += cookie.writeTo(r.output[from:])
		r.out1._addCRLFHeader(from)
		return true
	} else {
		return false
	}
}

func (r *server1Response) sendChain() error { return r.out1.sendChain() }

func (r *server1Response) echoHeaders() error { return r.out1.writeHeaders() }
func (r *server1Response) echoChain() error   { return r.out1.echoChain(r.request.IsHTTP1_1()) } // chunked only for HTTP/1.1

func (r *server1Response) addTrailer(name []byte, value []byte) bool {
	if r.request.VersionCode() == Version1_1 {
		return r.out1.addTrailer(name, value)
	}
	return true // HTTP/1.0 doesn't support http trailers.
}
func (r *server1Response) trailer(name []byte) (value []byte, ok bool) { return r.out1.trailer(name) }

func (r *server1Response) proxyPass1xx(backResp BackendResponse) bool {
	backResp.proxyDelHopHeaderFields()
	r.status = backResp.Status()
	if !backResp.proxyWalkHeaderLines(r, func(out httpOut, headerLine *pair, headerName []byte, lineValue []byte) bool {
		return out.insertHeader(headerLine.nameHash, headerName, lineValue) // some header fields (e.g. "connection") are restricted
	}) {
		return false
	}
	r.vector = r.fixedVector[0:3]
	r.vector[0] = r.controlData()
	r.vector[1] = r.addedHeaders()
	r.vector[2] = bytesCRLF
	// 1xx response has no content.
	if r.out1.writeVector() != nil {
		return false
	}
	// For next use.
	r.onEnd()
	r.onUse()
	return true
}
func (r *server1Response) proxyPassHeaders() error          { return r.out1.writeHeaders() }
func (r *server1Response) proxyPassBytes(data []byte) error { return r.out1.proxyPassBytes(data) }

func (r *server1Response) finalizeHeaders() { // add at most 256 bytes
	// date: Sun, 06 Nov 1994 08:49:37 GMT\r\n
	if r.iDate == 0 {
		clock := r.stream.(*server1Stream).conn.holder.stage.clock
		r.outputEdge += uint16(clock.writeDate1(r.output[r.outputEdge:]))
	}
	// expires: Sun, 06 Nov 1994 08:49:37 GMT\r\n
	if r.unixTimes.expires >= 0 {
		r.outputEdge += uint16(clockWriteHTTPDate1(r.output[r.outputEdge:], bytesExpires, r.unixTimes.expires))
	}
	// last-modified: Sun, 06 Nov 1994 08:49:37 GMT\r\n
	if r.unixTimes.lastModified >= 0 {
		r.outputEdge += uint16(clockWriteHTTPDate1(r.output[r.outputEdge:], bytesLastModified, r.unixTimes.lastModified))
	}
	conn := r.stream.(*server1Stream).conn
	if r.contentSize != -1 { // with content
		if !r.forbidFraming {
			if !r.isVague() { // content-length: >=0\r\n
				sizeBuffer := r.stream.buffer256() // enough for content-length
				n := i64ToDec(r.contentSize, sizeBuffer)
				r.out1._addFixedHeader(bytesContentLength, sizeBuffer[:n])
			} else if r.request.VersionCode() == Version1_1 { // transfer-encoding: chunked\r\n
				r.outputEdge += uint16(copy(r.output[r.outputEdge:], http1BytesTransferChunked))
			} else {
				// RFC 9112 (section 6.1):
				// A server MUST NOT send a response containing Transfer-Encoding unless
				// the corresponding request indicates HTTP/1.1 (or later minor revisions).
				conn.persistent = false // for HTTP/1.0 we have to close the connection anyway since there is no way to delimit the chunks
			}
		}
		// content-type: text/html\r\n
		if r.iContentType == 0 {
			r.outputEdge += uint16(copy(r.output[r.outputEdge:], http1BytesContentTypeHTML))
		}
	}
	if conn.persistent { // connection: keep-alive\r\n
		r.outputEdge += uint16(copy(r.output[r.outputEdge:], http1BytesConnectionKeepAlive))
	} else { // connection: close\r\n
		r.outputEdge += uint16(copy(r.output[r.outputEdge:], http1BytesConnectionClose))
	}
}
func (r *server1Response) finalizeVague() error {
	if r.request.VersionCode() == Version1_1 {
		return r.out1.finalizeVague()
	}
	return nil // HTTP/1.0 does nothing.
}

func (r *server1Response) addedHeaders() []byte { return r.output[0:r.outputEdge] }
func (r *server1Response) fixedHeaders() []byte { return http1BytesFixedResponseHeaders }

// server1Socket is the server-side HTTP/1 webSocket.
type server1Socket struct { // incoming and outgoing
	// Parent
	serverSocket_
	// Assocs
	so1 _http1Socket_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolServer1Socket sync.Pool

func getServer1Socket(stream *server1Stream) *server1Socket {
	// TODO
	return nil
}
func putServer1Socket(socket *server1Socket) {
	// TODO
}

func (s *server1Socket) onUse() {
	s.serverSocket_.onUse()
	s.so1.onUse(&s._httpSocket_)
}
func (s *server1Socket) onEnd() {
	s.serverSocket_.onEnd()
	s.so1.onEnd()
}

func (s *server1Socket) serverTodo1() {
	s.serverTodo()
	s.so1.todo1()
}

////////////////////////////////////////////////////////////////////////////////

func init() {
	RegisterBackend("http1Backend", func(compName string, stage *Stage) Backend {
		b := new(HTTP1Backend)
		b.OnCreate(compName, stage)
		return b
	})
}

// HTTP1Backend
type HTTP1Backend struct {
	// Parent
	httpBackend_[*http1Node]
	// States
}

func (b *HTTP1Backend) CreateNode(compName string) Node {
	node := new(http1Node)
	node.onCreate(compName, b.stage, b)
	b.AddNode(node)
	return node
}

func (b *HTTP1Backend) AcquireStream(servReq ServerRequest) (BackendStream, error) {
	return b.nodes[b.nodeIndexGet()].fetchStream()
}
func (b *HTTP1Backend) ReleaseStream(backStream BackendStream) {
	backStream1 := backStream.(*backend1Stream)
	backStream1.conn.holder.storeStream(backStream1)
}

// http1Node is a node in HTTP1Backend.
type http1Node struct {
	// Parent
	httpNode_[*HTTP1Backend, *backend1Conn]
	// States
}

func (n *http1Node) onCreate(compName string, stage *Stage, backend *HTTP1Backend) {
	n.httpNode_.onCreate(compName, stage, backend)
}

func (n *http1Node) OnConfigure() {
	n.httpNode_.onConfigure()
	if n.tlsMode {
		n.tlsConfig.InsecureSkipVerify = true
		n.tlsConfig.NextProtos = []string{"http/1.1"}
	}
}
func (n *http1Node) OnPrepare() {
	n.httpNode_.onPrepare()
}

func (n *http1Node) Maintain() { // runner
	n.LoopRun(time.Second, func(now time.Time) {
		// TODO: health check, markDown, markUp()
	})
	n.markDown()
	if size := n.closeIdle(); size > 0 {
		n.DecConns(size)
	}
	n.WaitConns() // TODO: max timeout?
	if DebugLevel() >= 2 {
		Printf("http1Node=%s done\n", n.compName)
	}
	n.backend.DecNode()
}

func (n *http1Node) fetchStream() (*backend1Stream, error) {
	backConn := n.pullConn()
	nodeDown := n.isDown()
	if backConn != nil {
		if !nodeDown && backConn.isAlive() && backConn.cumulativeStreams.Add(1) <= n.maxCumulativeStreamsPerConn {
			return backConn.newStream()
		}
		backConn.Close()
		n.DecConn()
	}
	if nodeDown {
		return nil, errNodeDown
	}
	var err error
	if n.UDSMode() {
		backConn, err = n._dialUDS()
	} else if n.TLSMode() {
		backConn, err = n._dialTLS()
	} else {
		backConn, err = n._dialTCP()
	}
	if err != nil {
		return nil, errNodeDown
	}
	n.IncConn()
	return backConn.newStream()
}
func (n *http1Node) _dialUDS() (*backend1Conn, error) {
	// TODO: dynamic address names?
	netConn, err := net.DialTimeout("unix", n.address, n.DialTimeout())
	if err != nil {
		n.markDown()
		return nil, err
	}
	if DebugLevel() >= 2 {
		Printf("http1Node=%s dial %s OK!\n", n.compName, n.address)
	}
	connID := n.nextConnID()
	rawConn, err := netConn.(*net.UnixConn).SyscallConn()
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return getBackend1Conn(connID, n, netConn, rawConn), nil
}
func (n *http1Node) _dialTLS() (*backend1Conn, error) {
	// TODO: dynamic address names?
	netConn, err := net.DialTimeout("tcp", n.address, n.DialTimeout())
	if err != nil {
		// TODO: handle ephemeral port exhaustion
		n.markDown()
		return nil, err
	}
	if DebugLevel() >= 2 {
		Printf("http1Node=%s dial %s OK!\n", n.compName, n.address)
	}
	connID := n.nextConnID()
	tlsConn := tls.Client(netConn, n.tlsConfig)
	if err := tlsConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		tlsConn.Close()
		return nil, err
	}
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return getBackend1Conn(connID, n, tlsConn, nil), nil
}
func (n *http1Node) _dialTCP() (*backend1Conn, error) {
	// TODO: dynamic address names?
	netConn, err := net.DialTimeout("tcp", n.address, n.DialTimeout())
	if err != nil {
		// TODO: handle ephemeral port exhaustion
		n.markDown()
		return nil, err
	}
	if DebugLevel() >= 2 {
		Printf("http1Node=%s dial %s OK!\n", n.compName, n.address)
	}
	connID := n.nextConnID()
	rawConn, err := netConn.(*net.TCPConn).SyscallConn()
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return getBackend1Conn(connID, n, netConn, rawConn), nil
}
func (n *http1Node) storeStream(backStream *backend1Stream) {
	backConn := backStream.conn
	backConn.delStream(backStream)

	if !n.isDown() && !backConn.isBroken() && backConn.isAlive() && backConn.persistent {
		if DebugLevel() >= 2 {
			Printf("Backend1Conn[node=%s id=%d] pushed\n", n.CompName(), backConn.id)
		}
		backConn.expireTime = time.Now().Add(n.idleTimeout)
		n.pushConn(backConn)
	} else {
		if DebugLevel() >= 2 {
			Printf("Backend1Conn[node=%s id=%d] closed\n", n.CompName(), backConn.id)
		}
		backConn.Close()
		n.DecConn()
	}
}

// backend1Conn is the backend-side HTTP/1 connection.
type backend1Conn struct {
	// Parent
	http1Conn_[*http1Node, *backend1Stream]
	// Mixins
	// Assocs
	stream backend1Stream // an http/1 connection has exactly one stream
	// Conn states (stocks)
	// Conn states (controlled)
	expireTime time.Time // when the conn is considered expired
	// Conn states (non-zeros)
	// Conn states (zeros)
}

var poolBackend1Conn sync.Pool

func getBackend1Conn(id int64, node *http1Node, netConn net.Conn, rawConn syscall.RawConn) *backend1Conn {
	var backConn *backend1Conn
	if x := poolBackend1Conn.Get(); x == nil {
		backConn = new(backend1Conn)
		backStream := &backConn.stream
		backResp, backReq := &backStream.response, &backStream.request
		backResp.stream = backStream
		backResp.in = backResp
		backReq.stream = backStream
		backReq.out = backReq
		backReq.response = backResp
	} else {
		backConn = x.(*backend1Conn)
	}
	backConn.onGet(id, node, netConn, rawConn)
	return backConn
}
func putBackend1Conn(backConn *backend1Conn) {
	backConn.onPut()
	poolBackend1Conn.Put(backConn)
}

func (c *backend1Conn) onGet(id int64, node *http1Node, netConn net.Conn, rawConn syscall.RawConn) {
	c.http1Conn_.onGet(id, node, netConn, rawConn)
}
func (c *backend1Conn) onPut() {
	c.expireTime = time.Time{}
	c.http1Conn_.onPut()
}

func (c *backend1Conn) isAlive() bool {
	return c.expireTime.IsZero() || time.Now().Before(c.expireTime)
}

func (c *backend1Conn) newStream() (*backend1Stream, error) { // used by http1Node
	// In HTTP/1.1 connections, streams are sequential, so we don't actually create them, simply reuse the only one
	backStream := &c.stream
	backStream.onUse(c, c.nextStreamID())
	return backStream, nil
}
func (c *backend1Conn) delStream(backStream *backend1Stream) { // used by http1Node
	// In HTTP/1.1 connections, streams are sequential, so we don't actually delete them, simply reuse the only one
	backStream.onEnd()
}

func (c *backend1Conn) Close() error {
	netConn := c.netConn
	putBackend1Conn(c)
	return netConn.Close()
}

// backend1Stream is the backend-side HTTP/1 stream.
type backend1Stream struct {
	// Parent
	http1Stream_[*backend1Conn]
	// Mixins
	// Assocs
	response backend1Response // the backend-side http/1 response
	request  backend1Request  // the backend-side http/1 request
	socket   *backend1Socket  // the backend-side http/1 webSocket
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (s *backend1Stream) onUse(conn *backend1Conn, id int64) { // for non-zeros
	s.http1Stream_.onUse(conn, id)

	s.response.onUse()
	s.request.onUse()
}
func (s *backend1Stream) onEnd() { // for zeros
	s.request.onEnd()
	s.response.onEnd()
	if s.socket != nil {
		s.socket.onEnd()
		s.socket = nil
	}

	s.http1Stream_.onEnd()
}

func (s *backend1Stream) Response() BackendResponse { return &s.response }
func (s *backend1Stream) Request() BackendRequest   { return &s.request }
func (s *backend1Stream) Socket() BackendSocket     { return nil } // TODO. See RFC 6455

// backend1Response is the backend-side HTTP/1 response.
type backend1Response struct { // incoming. needs parsing
	// Parent
	backendResponse_
	// Assocs
	in1 _http1In_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *backend1Response) onUse() {
	r.backendResponse_.onUse(Version1_1)
	r.in1.onUse(&r._httpIn_)
}
func (r *backend1Response) onEnd() {
	r.backendResponse_.onEnd()
	r.in1.onEnd()
}

func (r *backend1Response) recvHead() { // control data + header section
	if err := r.stream.setReadDeadline(); err != nil { // the entire response head must be received in one read timeout
		r.headResult = -1
		return
	}
	if !r.in1.growHead() { // r.input must be empty because we don't use pipelining in requests.
		// r.headResult is set.
		return
	}
	if !r._recvControlData() || !r.in1.recvHeaderLines() || !r.examineHead() {
		// r.headResult is set.
		return
	}
	r.tidyInput()
	if DebugLevel() >= 2 {
		Printf("[backend1Stream=%d]=======> [%s]\n", r.stream.ID(), r.input[r.head.from:r.head.edge])
	}
}
func (r *backend1Response) _recvControlData() bool { // status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF
	// HTTP-version = HTTP-name "/" DIGIT "." DIGIT
	// HTTP-name = %x48.54.54.50 ; "HTTP", case-sensitive
	if have := r.inputEdge - r.elemFore; have >= 9 {
		// r.elemFore -> ' '
		// r.inputEdge -> after ' ' or more
		r.elemFore += 8
	} else { // have < 9, but len("HTTP/1.X ") = 9.
		// r.elemFore at 'H' -> ' '
		// r.inputEdge at "TTP/1.X " -> after ' '
		r.elemFore = r.inputEdge - 1
		for i, n := int32(0), 9-have; i < n; i++ {
			if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
				return false
			}
		}
	}
	if !bytes.Equal(r.input[r.elemBack:r.elemFore], bytesHTTP1_1) { // for HTTP/1, only HTTP/1.1 is supported in backend side
		r.headResult = StatusHTTPVersionNotSupported
		return false
	}

	// Skip SP
	if r.input[r.elemFore] != ' ' {
		goto invalid
	}
	if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
		return false
	}

	// status-code = 3DIGIT
	if b := r.input[r.elemFore]; b >= '1' && b <= '9' {
		r.status = int16(b-'0') * 100
	} else {
		goto invalid
	}
	if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
		return false
	}
	if b := r.input[r.elemFore]; b >= '0' && b <= '9' {
		r.status += int16(b-'0') * 10
	} else {
		goto invalid
	}
	if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
		return false
	}
	if b := r.input[r.elemFore]; b >= '0' && b <= '9' {
		r.status += int16(b - '0')
	} else {
		goto invalid
	}
	if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
		return false
	}

	// Skip SP
	if r.input[r.elemFore] != ' ' {
		goto invalid
	}
	if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
		return false
	}

	// reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )
	for {
		if b := r.input[r.elemFore]; b == '\n' {
			break
		}
		if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
			return false
		}
	}
	r.receiving = httpSectionHeaders
	// Skip '\n'
	if r.elemFore++; r.elemFore == r.inputEdge && !r.in1.growHead() {
		return false
	}
	return true
invalid:
	r.headResult, r.failReason = StatusBadRequest, "invalid character in control"
	return false
}
func (r *backend1Response) tidyInput() {
	// r.elemFore is at the beginning of content (if exists) or next response (if exists and is pipelined).
	if r.contentSize == -1 { // no content
		r.contentReceived = true
		if r.elemFore < r.inputEdge { // still has data
			// RFC 9112 (section 6.3):
			// If the final response to the last request on a connection has been completely received
			// and there remains additional data to read, a user agent MAY discard the remaining data
			// or attempt to determine if that data belongs as part of the prior message body, which
			// might be the case if the prior message's Content-Length value is incorrect. A client
			// MUST NOT process, cache, or forward such extra data as a separate response, since such
			// behavior would be vulnerable to cache poisoning.

			// TODO: log? possible response splitting
		}
		return
	}
	// content exists (sized or vague)
	r.imme.set(r.elemFore, r.inputEdge)
	if r.contentSize >= 0 { // sized mode
		if immeSize := int64(r.imme.size()); immeSize >= r.contentSize {
			r.contentReceived = true
			if immeSize > r.contentSize { // still has data
				// TODO: log? possible response splitting
			}
			r.receivedSize = r.contentSize
			r.contentText = r.input[r.elemFore : r.elemFore+int32(r.contentSize)] // exact.
			r.contentTextKind = httpContentTextInput
		}
	} else { // vague mode
		// We don't know the size of vague content. Let chunked receivers to decide & clean r.input.
	}
}

func (r *backend1Response) readContent() (data []byte, err error) { return r.in1.readContent() }

// backend1Request is the backend-side HTTP/1 request.
type backend1Request struct { // outgoing. needs building
	// Parent
	backendRequest_
	// Assocs
	out1 _http1Out_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

func (r *backend1Request) onUse() {
	r.backendRequest_.onUse(Version1_1)
	r.out1.onUse(&r._httpOut_)
}
func (r *backend1Request) onEnd() {
	r.backendRequest_.onEnd()
	r.out1.onEnd()
}

func (r *backend1Request) addHeader(name []byte, value []byte) bool {
	return r.out1.addHeader(name, value)
}
func (r *backend1Request) header(name []byte) (value []byte, ok bool) { return r.out1.header(name) }
func (r *backend1Request) hasHeader(name []byte) bool                 { return r.out1.hasHeader(name) }
func (r *backend1Request) delHeader(name []byte) (deleted bool)       { return r.out1.delHeader(name) }
func (r *backend1Request) delHeaderAt(i uint8)                        { r.out1.delHeaderAt(i) }

func (r *backend1Request) AddCookie(name string, value string) bool { // cookie: foo=bar; xyz=baz
	// TODO. need some space to place the cookie. use stream.riskyMake()?
	return false
}
func (r *backend1Request) proxyCopyCookies(servReq ServerRequest) bool { // NOTE: merge all cookies into one "cookie" header field
	headerSize := len(bytesCookie) + len(bytesColonSpace) // `cookie: `
	servReq.proxyWalkCookies(func(cookie *pair, cookieName []byte, cookieValue []byte) bool {
		headerSize += len(cookieName) + 1 + len(cookieValue) + 2 // `name=value; `
		return true
	})
	if from, _, ok := r.growHeaders(headerSize); ok {
		from += copy(r.output[from:], bytesCookie)
		r.output[from] = ':'
		r.output[from+1] = ' '
		from += 2
		servReq.proxyWalkCookies(func(cookie *pair, cookieName []byte, cookieValue []byte) bool {
			from += copy(r.output[from:], cookieName)
			r.output[from] = '='
			from++
			from += copy(r.output[from:], cookieValue)
			r.output[from] = ';'
			r.output[from+1] = ' '
			from += 2
			return true
		})
		r.output[from-2] = '\r'
		r.output[from-1] = '\n'
		return true
	} else {
		return false
	}
}

func (r *backend1Request) sendChain() error { return r.out1.sendChain() }

func (r *backend1Request) echoHeaders() error { return r.out1.writeHeaders() }
func (r *backend1Request) echoChain() error   { return r.out1.echoChain(true) } // we always use HTTP/1.1 chunked

func (r *backend1Request) addTrailer(name []byte, value []byte) bool {
	return r.out1.addTrailer(name, value)
}
func (r *backend1Request) trailer(name []byte) (value []byte, ok bool) { return r.out1.trailer(name) }

func (r *backend1Request) proxySetMethodURI(method []byte, uri []byte, hasContent bool) bool { // METHOD uri HTTP/1.1\r\n
	controlSize := len(method) + 1 + len(uri) + 1 + len(bytesHTTP1_1) + len(bytesCRLF)
	if from, edge, ok := r._growFields(controlSize); ok {
		from += copy(r.output[from:], method)
		r.output[from] = ' '
		from++
		from += copy(r.output[from:], uri)
		r.output[from] = ' '
		from++
		from += copy(r.output[from:], bytesHTTP1_1) // we always use HTTP/1.1
		r.output[from] = '\r'
		r.output[from+1] = '\n'
		if !hasContent {
			r.forbidContent = true
			r.forbidFraming = true
		}
		r.controlEdge = uint16(edge)
		return true
	} else {
		return false
	}
}
func (r *backend1Request) proxySetAuthority(hostname []byte, colonport []byte) bool {
	if r.stream.TLSMode() {
		if bytes.Equal(colonport, bytesColonport443) {
			colonport = nil
		}
	} else if bytes.Equal(colonport, bytesColonport80) {
		colonport = nil
	}
	headerSize := len(bytesHost) + len(bytesColonSpace) + len(hostname) + len(colonport) + len(bytesCRLF) // host: xxx\r\n
	if from, _, ok := r._growFields(headerSize); ok {
		from += copy(r.output[from:], bytesHost)
		r.output[from] = ':'
		r.output[from+1] = ' '
		from += 2
		from += copy(r.output[from:], hostname)
		from += copy(r.output[from:], colonport)
		r.out1._addCRLFHeader(from)
		return true
	} else {
		return false
	}
}

func (r *backend1Request) proxyPassHeaders() error          { return r.out1.writeHeaders() }
func (r *backend1Request) proxyPassBytes(data []byte) error { return r.out1.proxyPassBytes(data) }

func (r *backend1Request) finalizeHeaders() { // add at most 256 bytes
	// if-modified-since: Sun, 06 Nov 1994 08:49:37 GMT\r\n
	if r.unixTimes.ifModifiedSince >= 0 {
		r.outputEdge += uint16(clockWriteHTTPDate1(r.output[r.outputEdge:], bytesIfModifiedSince, r.unixTimes.ifModifiedSince))
	}
	// if-unmodified-since: Sun, 06 Nov 1994 08:49:37 GMT\r\n
	if r.unixTimes.ifUnmodifiedSince >= 0 {
		r.outputEdge += uint16(clockWriteHTTPDate1(r.output[r.outputEdge:], bytesIfUnmodifiedSince, r.unixTimes.ifUnmodifiedSince))
	}
	if r.contentSize != -1 { // with content
		if !r.forbidFraming {
			if r.isVague() { // transfer-encoding: chunked\r\n
				r.outputEdge += uint16(copy(r.output[r.outputEdge:], http1BytesTransferChunked))
			} else { // content-length: >=0\r\n
				sizeBuffer := r.stream.buffer256() // enough for content-length
				n := i64ToDec(r.contentSize, sizeBuffer)
				r.out1._addFixedHeader(bytesContentLength, sizeBuffer[:n])
			}
		}
		// content-type: application/octet-stream\r\n
		if r.iContentType == 0 {
			r.outputEdge += uint16(copy(r.output[r.outputEdge:], http1BytesContentTypeStream))
		}
	}
	if r.addTETrailers {
		r.outputEdge += uint16(copy(r.output[r.outputEdge:], http1BytesTETrailers))
		r.outputEdge += uint16(copy(r.output[r.outputEdge:], http1BytesConnectionAliveTE))
	} else {
		// connection: keep-alive\r\n
		r.outputEdge += uint16(copy(r.output[r.outputEdge:], http1BytesConnectionKeepAlive))
	}
}
func (r *backend1Request) finalizeVague() error { return r.out1.finalizeVague() } // we always use http/1.1 in the backend side.

func (r *backend1Request) addedHeaders() []byte { return r.output[r.controlEdge:r.outputEdge] }
func (r *backend1Request) fixedHeaders() []byte { return http1BytesFixedRequestHeaders }

// backend1Socket is the backend-side HTTP/1 webSocket.
type backend1Socket struct { // incoming and outgoing
	// Parent
	backendSocket_
	// Assocs
	so1 _http1Socket_
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	// Stream states (zeros)
}

var poolBackend1Socket sync.Pool

func getBackend1Socket(stream *backend1Stream) *backend1Socket {
	// TODO
	return nil
}
func putBackend1Socket(socket *backend1Socket) {
	// TODO
}

func (s *backend1Socket) onUse() {
	s.backendSocket_.onUse()
	s.so1.onUse(&s._httpSocket_)
}
func (s *backend1Socket) onEnd() {
	s.backendSocket_.onEnd()
	s.so1.onEnd()
}

func (s *backend1Socket) backendTodo1() {
	s.backendTodo()
	s.so1.todo1()
}

////////////////////////////////////////////////////////////////////////////////

var http1Status = [16]byte{'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', 'N', 'N', 'N', ' ', 'X', '\r', '\n'}
var http1Controls = [...][]byte{ // size: 512*24B=12K
	// 1XX
	StatusContinue:           []byte("HTTP/1.1 100 Continue\r\n"),
	StatusSwitchingProtocols: []byte("HTTP/1.1 101 Switching Protocols\r\n"),
	StatusProcessing:         []byte("HTTP/1.1 102 Processing\r\n"),
	StatusEarlyHints:         []byte("HTTP/1.1 103 Early Hints\r\n"),
	// 2XX
	StatusOK:                         []byte("HTTP/1.1 200 OK\r\n"),
	StatusCreated:                    []byte("HTTP/1.1 201 Created\r\n"),
	StatusAccepted:                   []byte("HTTP/1.1 202 Accepted\r\n"),
	StatusNonAuthoritativeInfomation: []byte("HTTP/1.1 203 Non-Authoritative Information\r\n"),
	StatusNoContent:                  []byte("HTTP/1.1 204 No Content\r\n"),
	StatusResetContent:               []byte("HTTP/1.1 205 Reset Content\r\n"),
	StatusPartialContent:             []byte("HTTP/1.1 206 Partial Content\r\n"),
	StatusMultiStatus:                []byte("HTTP/1.1 207 Multi-Status\r\n"),
	StatusAlreadyReported:            []byte("HTTP/1.1 208 Already Reported\r\n"),
	StatusIMUsed:                     []byte("HTTP/1.1 226 IM Used\r\n"),
	// 3XX
	StatusMultipleChoices:   []byte("HTTP/1.1 300 Multiple Choices\r\n"),
	StatusMovedPermanently:  []byte("HTTP/1.1 301 Moved Permanently\r\n"),
	StatusFound:             []byte("HTTP/1.1 302 Found\r\n"),
	StatusSeeOther:          []byte("HTTP/1.1 303 See Other\r\n"),
	StatusNotModified:       []byte("HTTP/1.1 304 Not Modified\r\n"),
	StatusUseProxy:          []byte("HTTP/1.1 305 Use Proxy\r\n"),
	StatusTemporaryRedirect: []byte("HTTP/1.1 307 Temporary Redirect\r\n"),
	StatusPermanentRedirect: []byte("HTTP/1.1 308 Permanent Redirect\r\n"),
	// 4XX
	StatusBadRequest:                  []byte("HTTP/1.1 400 Bad Request\r\n"),
	StatusUnauthorized:                []byte("HTTP/1.1 401 Unauthorized\r\n"),
	StatusPaymentRequired:             []byte("HTTP/1.1 402 Payment Required\r\n"),
	StatusForbidden:                   []byte("HTTP/1.1 403 Forbidden\r\n"),
	StatusNotFound:                    []byte("HTTP/1.1 404 Not Found\r\n"),
	StatusMethodNotAllowed:            []byte("HTTP/1.1 405 Method Not Allowed\r\n"),
	StatusNotAcceptable:               []byte("HTTP/1.1 406 Not Acceptable\r\n"),
	StatusProxyAuthenticationRequired: []byte("HTTP/1.1 407 Proxy Authentication Required\r\n"),
	StatusRequestTimeout:              []byte("HTTP/1.1 408 Request Timeout\r\n"),
	StatusConflict:                    []byte("HTTP/1.1 409 Conflict\r\n"),
	StatusGone:                        []byte("HTTP/1.1 410 Gone\r\n"),
	StatusLengthRequired:              []byte("HTTP/1.1 411 Length Required\r\n"),
	StatusPreconditionFailed:          []byte("HTTP/1.1 412 Precondition Failed\r\n"),
	StatusContentTooLarge:             []byte("HTTP/1.1 413 Content Too Large\r\n"),
	StatusURITooLong:                  []byte("HTTP/1.1 414 URI Too Long\r\n"),
	StatusUnsupportedMediaType:        []byte("HTTP/1.1 415 Unsupported Media Type\r\n"),
	StatusRangeNotSatisfiable:         []byte("HTTP/1.1 416 Range Not Satisfiable\r\n"),
	StatusExpectationFailed:           []byte("HTTP/1.1 417 Expectation Failed\r\n"),
	StatusMisdirectedRequest:          []byte("HTTP/1.1 421 Misdirected Request\r\n"),
	StatusUnprocessableEntity:         []byte("HTTP/1.1 422 Unprocessable Entity\r\n"),
	StatusLocked:                      []byte("HTTP/1.1 423 Locked\r\n"),
	StatusFailedDependency:            []byte("HTTP/1.1 424 Failed Dependency\r\n"),
	StatusTooEarly:                    []byte("HTTP/1.1 425 Too Early\r\n"),
	StatusUpgradeRequired:             []byte("HTTP/1.1 426 Upgrade Required\r\n"),
	StatusPreconditionRequired:        []byte("HTTP/1.1 428 Precondition Required\r\n"),
	StatusTooManyRequests:             []byte("HTTP/1.1 429 Too Many Requests\r\n"),
	StatusRequestHeaderFieldsTooLarge: []byte("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
	StatusUnavailableForLegalReasons:  []byte("HTTP/1.1 451 Unavailable For Legal Reasons\r\n"),
	// 5XX
	StatusInternalServerError:           []byte("HTTP/1.1 500 Internal Server Error\r\n"),
	StatusNotImplemented:                []byte("HTTP/1.1 501 Not Implemented\r\n"),
	StatusBadGateway:                    []byte("HTTP/1.1 502 Bad Gateway\r\n"),
	StatusServiceUnavailable:            []byte("HTTP/1.1 503 Service Unavailable\r\n"),
	StatusGatewayTimeout:                []byte("HTTP/1.1 504 Gateway Timeout\r\n"),
	StatusHTTPVersionNotSupported:       []byte("HTTP/1.1 505 HTTP Version Not Supported\r\n"),
	StatusVariantAlsoNegotiates:         []byte("HTTP/1.1 506 Variant Also Negotiates\r\n"),
	StatusInsufficientStorage:           []byte("HTTP/1.1 507 Insufficient Storage\r\n"),
	StatusLoopDetected:                  []byte("HTTP/1.1 508 Loop Detected\r\n"),
	StatusNotExtended:                   []byte("HTTP/1.1 510 Not Extended\r\n"),
	StatusNetworkAuthenticationRequired: []byte("HTTP/1.1 511 Network Authentication Required\r\n"),
}

var ( // HTTP/1 byteses
	http1BytesContinue             = []byte("HTTP/1.1 100 Continue\r\n\r\n")
	http1BytesConnectionClose      = []byte("connection: close\r\n")
	http1BytesConnectionKeepAlive  = []byte("connection: keep-alive\r\n")
	http1BytesConnectionAliveTE    = []byte("connection: keep-alive, te\r\n")
	http1BytesContentTypeStream    = []byte("content-type: application/octet-stream\r\n")
	http1BytesContentTypeHTML      = []byte("content-type: text/html\r\n")
	http1BytesTransferChunked      = []byte("transfer-encoding: chunked\r\n")
	http1BytesTETrailers           = []byte("te: trailers\r\n")
	http1BytesVaryEncoding         = []byte("vary: accept-encoding\r\n")
	http1BytesLocationHTTP         = []byte("location: http://")
	http1BytesLocationHTTPS        = []byte("location: https://")
	http1BytesFixedRequestHeaders  = []byte("client: gorox\r\n\r\n")
	http1BytesFixedResponseHeaders = []byte("server: gorox\r\n\r\n")
	http1BytesZeroCRLF             = []byte("0\r\n")
	http1BytesZeroCRLFCRLF         = []byte("0\r\n\r\n")
)
