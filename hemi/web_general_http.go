// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// HTTP types and protocol elements. See RFC 9110.

package hemi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// httpHolder
type httpHolder interface { // for _httpHolder_
	// Imports
	holder
	contentSaver
	// Methods
	MaxMemoryContentSize() int32 // allowed to load into memory
}

// _httpHolder_ is a mixin.
type _httpHolder_ struct { // for httpNode_, httpServer_, and httpGate_
	// Mixins
	_contentSaver_ // so http messages can save their large contents in local file system.
	// States
	maxCumulativeStreamsPerConn int32 // max cumulative streams of one conn. 0 means infinite
	maxMemoryContentSize        int32 // max content size that can be loaded into memory directly
}

func (h *_httpHolder_) onConfigure(comp Component, defaultRecv time.Duration, defaultSend time.Duration, defaultDir string) {
	h._contentSaver_.onConfigure(comp, defaultRecv, defaultSend, defaultDir)

	// .maxCumulativeStreamsPerConn
	comp.ConfigureInt32("maxCumulativeStreamsPerConn", &h.maxCumulativeStreamsPerConn, func(value int32) error {
		if value >= 0 {
			return nil
		}
		return errors.New(".maxCumulativeStreamsPerConn has an invalid value")
	}, 1000)

	// .maxMemoryContentSize
	comp.ConfigureInt32("maxMemoryContentSize", &h.maxMemoryContentSize, func(value int32) error {
		if value > 0 && value <= _1G { // DO NOT CHANGE THIS, otherwise integer overflow may occur
			return nil
		}
		return errors.New(".maxMemoryContentSize has an invalid value")
	}, _16M)
}
func (h *_httpHolder_) onPrepare(comp Component, perm os.FileMode) {
	h._contentSaver_.onPrepare(comp, perm)
}

func (h *_httpHolder_) MaxMemoryContentSize() int32 { return h.maxMemoryContentSize }

// httpConn
type httpConn interface { // for *http[1-3]Conn
	ID() int64
	Holder() httpHolder
	UDSMode() bool
	TLSMode() bool
	MakeTempName(dst []byte, unixTime int64) int
	remoteAddr() net.Addr
	markBroken()
	isBroken() bool
}

// httpConn_ is a parent.
type httpConn_[H httpHolder] struct { // for http[1-3]Conn_
	// Conn states (stocks)
	// Conn states (controlled)
	// Conn states (non-zeros)
	id     int64 // the conn id
	holder H     // HTTPNode or httpGate
	// Conn states (zeros)
	cumulativeStreams atomic.Int32 // cumulative num of streams served or fired by this conn
	broken            atomic.Bool  // is conn broken?
	counter           atomic.Int64 // can be used to generate a random number
}

func (c *httpConn_[H]) onGet(id int64, holder H) {
	c.id = id
	c.holder = holder
}
func (c *httpConn_[H]) onPut() {
	var null H // nil
	c.holder = null
	c.cumulativeStreams.Store(0)
	c.broken.Store(false)
	c.counter.Store(0)
}

func (c *httpConn_[H]) ID() int64 { return c.id }

func (c *httpConn_[H]) Holder() httpHolder { return c.holder }

func (c *httpConn_[H]) UDSMode() bool { return c.holder.UDSMode() }
func (c *httpConn_[H]) TLSMode() bool { return c.holder.TLSMode() }
func (c *httpConn_[H]) MakeTempName(dst []byte, unixTime int64) int {
	return makeTempName(dst, c.holder.Stage().ID(), unixTime, c.id, c.counter.Add(1))
}

func (c *httpConn_[H]) markBroken()    { c.broken.Store(true) }
func (c *httpConn_[H]) isBroken() bool { return c.broken.Load() }

// httpStream
type httpStream interface { // for *http[1-3]Stream
	Holder() httpHolder
	ID() int64
	UDSMode() bool
	TLSMode() bool
	MakeTempName(dst []byte, unixTime int64) int
	remoteAddr() net.Addr
	markBroken()    // mark stream as broken
	isBroken() bool // returns true if either side of the stream is broken
	buffer256() []byte
	riskyMake(size int) []byte
	setReadDeadline() error
	setWriteDeadline() error
	read(dst []byte) (int, error)
	readFull(dst []byte) (int, error)
	write(src []byte) (int, error)
	writeVec(srcVec *net.Buffers) (int64, error)
}

// httpStream_ is a parent.
type httpStream_[C httpConn] struct { // for http[1-3]Stream_
	// Assocs
	conn C // the http connection
	// Stream states (stocks)
	stockBuffer [256]byte // a (fake) buffer to workaround Go's conservative escape analysis. must be >= 256 bytes so names can be placed into
	// Stream states (controlled)
	// Stream states (non-zeros)
	region Region // a region-based memory pool
	// Stream states (zeros)
}

func (s *httpStream_[C]) onUse(conn C) {
	s.conn = conn
	s.region.Init()
}
func (s *httpStream_[C]) onEnd() {
	var null C // nil
	s.conn = null
	s.region.Free()
}

func (s *httpStream_[C]) Holder() httpHolder { return s.conn.Holder() }
func (s *httpStream_[C]) UDSMode() bool      { return s.conn.UDSMode() }
func (s *httpStream_[C]) TLSMode() bool      { return s.conn.TLSMode() }
func (s *httpStream_[C]) MakeTempName(dst []byte, unixTime int64) int {
	return s.conn.MakeTempName(dst, unixTime)
}
func (s *httpStream_[C]) remoteAddr() net.Addr { return s.conn.remoteAddr() }

func (s *httpStream_[C]) buffer256() []byte         { return s.stockBuffer[:] }
func (s *httpStream_[C]) riskyMake(size int) []byte { return s.region.Make(size) }

// httpIn
type httpIn interface {
	ContentSize() int64
	IsVague() bool
	HasTrailers() bool

	readContent() (data []byte, err error)
	examineTail() bool
	proxyDelHopFieldLines(kind int8)
	proxyWalkTrailerLines(out httpOut, callback func(out httpOut, trailerLine *pair, trailerName []byte, lineValue []byte) bool) bool
}

// _httpIn_ is a mixin.
type _httpIn_ struct { // for backendResponse_ and serverRequest_. incoming message, needs parsing
	// Assocs
	stream httpStream // *backend[1-3]Stream, *server[1-3]Stream
	in     httpIn     // *backend[1-3]Response, *server[1-3]Request
	// Stream states (stocks)
	stockInput  [1536]byte // for r.input
	stockArray  [768]byte  // for r.array
	stockPrimes [40]pair   // for r.primes. 960B
	stockExtras [30]pair   // for r.extras. 720B
	// Stream states (controlled)
	inputNext      int32    // HTTP/1.x request only. next request begins from r.input[r.inputNext]. exists because HTTP/1.1 supports pipelining
	inputEdge      int32    // edge position of current message head is at r.input[r.inputEdge]. placed here to make it compatible with HTTP/1.1 pipelining
	mainPair       pair     // to overcome the limitation of Go's escape analysis when receiving incoming pairs
	contentCodings [4]uint8 // known content-encoding flags, controlled by r.numContentCodings. see httpCodingXXX for values
	acceptCodings  [4]uint8 // known accept-encoding flags, controlled by r.numAcceptCodings. see httpCodingXXX for values
	// Stream states (non-zeros)
	input                []byte        // bytes of raw incoming message heads. [<r.stockInput>/4K/16K]
	array                []byte        // store parsed input and dynamic incoming data. [<r.stockArray>/4K/16K/64K1/(make <= 1G)]
	primes               []pair        // hold prime queries, headerLines(main+subs), cookies, forms, and trailerLines(main+subs). [<r.stockPrimes>/max]
	extras               []pair        // hold extra queries, headerLines(main+subs), cookies, forms, trailerLines(main+subs), and params. [<r.stockExtras>/max]
	recvTimeout          time.Duration // timeout to recv the whole message content. zero means no timeout
	maxContentSize       int64         // max content size allowed for current message. if the content is vague, size will be calculated on receiving
	maxMemoryContentSize int32         // max content size allowed for loading the content into memory. some content types are not allowed to load into memory
	_                    int32         // padding
	contentSize          int64         // size info about incoming content. -2: vague content, -1: no content, >=0: content size
	httpVersion          uint8         // Version1_0, Version1_1, Version2, Version3
	asResponse           bool          // treat this incoming message as a response? i.e. backend response
	keepAlive            int8          // -1: no connection header field, 0: connection close, 1: connection keep-alive
	_                    byte          // padding
	headResult           int16         // result of receiving message head. values are as same as http status for convenience
	bodyResult           int16         // result of receiving message body. values are as same as http status for convenience
	// Stream states (zeros)
	failReason  string    // the fail reason of headResult or bodyResult
	bodyWindow  []byte    // a window used for receiving body. for HTTP/1.x, sizes must be same with r.input. [HTTP/1.x=<none>/16K, HTTP/2/3=<none>/4K/16K/64K1]
	bodyTime    time.Time // the time when first body read operation is performed on this stream
	contentText []byte    // if loadable, the received and loaded content of current message is at r.contentText[:r.receivedSize]. [<none>/r.input/4K/16K/64K1/(make)]
	contentFile *os.File  // used by r.proxyTakeContent(), if content is tempFile. will be closed on stream ends
	_httpIn0              // all values in this struct must be zero by default!
}
type _httpIn0 struct { // for fast reset, entirely
	elemBack          int32   // element begins from. for parsing elements in control & headerLines & content & trailerLines
	elemFore          int32   // element spanning to. for parsing elements in control & headerLines & content & trailerLines
	head              span    // head (control data + header section) of current message -> r.input. set after head is received. only for debugging
	imme              span    // HTTP/1.x only. immediate data after current message head is at r.input[r.imme.from:r.imme.edge]
	hasExtra          [8]bool // has extra pairs? see pairXXX for indexes
	dateTime          int64   // parsed unix time of the date header field
	arrayEdge         int32   // next usable position of r.array begins from r.array[r.arrayEdge]. used when writing r.array
	arrayKind         int8    // kind of current r.array. see arrayKindXXX
	receiving         int8    // what message section are we currently receiving? see httpSectionXXX
	headerLines       zone    // header lines ->r.primes
	hasRevisers       bool    // are there any incoming revisers hooked on this incoming message?
	upgradeSocket     bool    // upgrade: websocket?
	acceptGzip        bool    // does the peer accept gzip content coding? i.e. accept-encoding: gzip
	acceptBrotli      bool    // does the peer accept brotli content coding? i.e. accept-encoding: br
	numContentCodings int8    // num of content-encoding flags, controls r.contentCodings
	numAcceptCodings  int8    // num of accept-encoding flags, controls r.acceptCodings
	iContentLength    uint8   // index of content-length header line in r.primes
	iContentLocation  uint8   // index of content-location header line in r.primes
	iContentRange     uint8   // index of content-range header line in r.primes
	iContentType      uint8   // index of content-type header line in r.primes
	iDate             uint8   // index of date header line in r.primes
	_                 [3]byte // padding
	zAccept           zone    // zone of accept header lines in r.primes. may not be continuous
	zAcceptEncoding   zone    // zone of accept-encoding header lines in r.primes. may not be continuous
	zCacheControl     zone    // zone of cache-control header lines in r.primes. may not be continuous
	zConnection       zone    // zone of connection header lines in r.primes. may not be continuous
	zContentEncoding  zone    // zone of content-encoding header lines in r.primes. may not be continuous
	zContentLanguage  zone    // zone of content-language header lines in r.primes. may not be continuous
	zKeepAlive        zone    // zone of keep-alive header lines in r.primes. may not be continuous
	zProxyConnection  zone    // zone of proxy-connection header lines in r.primes. may not be continuous
	zTrailer          zone    // zone of trailer header lines in r.primes. may not be continuous
	zTransferEncoding zone    // zone of transfer-encoding header lines in r.primes. may not be continuous
	zUpgrade          zone    // zone of upgrade header lines in r.primes. may not be continuous
	zVia              zone    // zone of via header lines in r.primes. may not be continuous
	contentReceived   bool    // is the content received? true if the message has no content or the content is received, otherwise false
	contentTextKind   int8    // kind of current r.contentText if it is text. see httpContentTextXXX
	receivedSize      int64   // bytes of currently received content. used and calculated by both sized & vague content receiver when receiving
	chunkSize         int64   // left size of current chunk if the chunk is too large to receive in one call. HTTP/1.1 chunked only
	chunkBack         int32   // for parsing chunked elements. HTTP/1.1 chunked only
	chunkFore         int32   // for parsing chunked elements. HTTP/1.1 chunked only
	chunkEdge         int32   // edge position of the filled chunked data in r.bodyWindow. HTTP/1.1 chunked only
	transferChunked   bool    // transfer-encoding: chunked? HTTP/1.1 only
	overChunked       bool    // for HTTP/1.1 requests, if chunked receiver over received in r.bodyWindow, then r.bodyWindow will be used as r.input on ends
	trailerLines      zone    // trailer lines -> r.primes. set after trailer section is received and parsed
}

func (r *_httpIn_) onUse(httpVersion uint8, asResponse bool) { // for non-zeros
	if httpVersion >= Version2 || asResponse { // we don't use http/1.1 request pipelining in the backend side.
		r.input = r.stockInput[:]
	} else { // must be http/1.x server side.
		// HTTP/1.1 servers support request pipelining, so input related are not set here.
	}
	r.array = r.stockArray[:]
	r.primes = r.stockPrimes[0:1:cap(r.stockPrimes)] // use append(). r.primes[0] is skipped due to zero value of pair indexes.
	r.extras = r.stockExtras[0:0:cap(r.stockExtras)] // use append()
	holder := r.stream.Holder()
	r.recvTimeout = holder.RecvTimeout()
	r.maxContentSize = holder.MaxContentSize()
	r.maxMemoryContentSize = holder.MaxMemoryContentSize()
	r.contentSize = -1 // no content
	r.httpVersion = httpVersion
	r.asResponse = asResponse
	r.keepAlive = -1 // no connection header field
	r.headResult = StatusOK
	r.bodyResult = StatusOK
}
func (r *_httpIn_) onEnd() { // for zeros
	if r.httpVersion >= Version2 || r.asResponse { // as we don't pipeline outgoing requests, incoming responses are not pipelined too.
		if cap(r.input) != cap(r.stockInput) {
			PutNK(r.input)
		}
		r.input = nil
		r.inputNext, r.inputEdge = 0, 0
	} else { // must be http/1.x server side.
		// HTTP/1.1 servers support request pipelining, so input related are not reset here.
	}
	if r.arrayKind == arrayKindPool {
		PutNK(r.array)
	}
	r.array = nil // array of other kinds is only a reference, so just reset.
	if cap(r.primes) != cap(r.stockPrimes) {
		putPairs(r.primes)
		r.primes = nil
	}
	if cap(r.extras) != cap(r.stockExtras) {
		putPairs(r.extras)
		r.extras = nil
	}

	r.failReason = ""

	if r.inputNext != 0 { // only happens in HTTP/1.1 server side request pipelining
		if r.overChunked { // only happens in HTTP/1.1 chunked mode
			// Use bytes over received in r.bodyWindow as new r.input.
			// This means the size list for r.bodyWindow must sync with r.input!
			if cap(r.input) != cap(r.stockInput) {
				PutNK(r.input)
			}
			r.input = r.bodyWindow // use r.bodyWindow as new r.input
		}
		// slide r.input. r.inputNext and r.inputEdge have already been set
		copy(r.input, r.input[r.inputNext:r.inputEdge])
		r.inputEdge -= r.inputNext
		r.inputNext = 0
	} else if r.bodyWindow != nil { // r.bodyWindow was used to receive content and failed to free. we free it here.
		PutNK(r.bodyWindow)
	}
	r.bodyWindow = nil

	r.bodyTime = time.Time{}

	if r.contentTextKind == httpContentTextPool {
		PutNK(r.contentText)
	}
	r.contentText = nil // contentText of other kinds is only a reference, so just reset.

	if r.contentFile != nil {
		r.contentFile.Close()
		if DebugLevel() >= 2 {
			Println("contentFile is left as is, not removed!")
		} else if err := os.Remove(r.contentFile.Name()); err != nil {
			// TODO: log err?
		}
		r.contentFile = nil
	}

	r._httpIn0 = _httpIn0{}
}

func (r *_httpIn_) RiskyMake(size int) []byte { return r.stream.riskyMake(size) }
func (r *_httpIn_) RemoteAddr() net.Addr      { return r.stream.remoteAddr() }

func (r *_httpIn_) VersionCode() uint8   { return r.httpVersion }
func (r *_httpIn_) IsHTTP1() bool        { return r.httpVersion <= Version1_1 }
func (r *_httpIn_) IsHTTP1_0() bool      { return r.httpVersion == Version1_0 }
func (r *_httpIn_) IsHTTP1_1() bool      { return r.httpVersion == Version1_1 }
func (r *_httpIn_) IsHTTP2() bool        { return r.httpVersion == Version2 }
func (r *_httpIn_) IsHTTP3() bool        { return r.httpVersion == Version3 }
func (r *_httpIn_) Version() string      { return httpVersionStrings[r.httpVersion] }
func (r *_httpIn_) RiskyVersion() []byte { return httpVersionByteses[r.httpVersion] }

func (r *_httpIn_) KeepAlive() bool   { return r.keepAlive == 1 } // -1 was excluded priorly. either 0 or 1 here
func (r *_httpIn_) HeadResult() int16 { return r.headResult }
func (r *_httpIn_) BodyResult() int16 { return r.bodyResult }

func (r *_httpIn_) addHeaderLine(headerLine *pair) bool { // as prime
	if edge, ok := r._addPrime(headerLine); ok {
		r.headerLines.edge = edge
		return true
	}
	r.headResult, r.failReason = StatusRequestHeaderFieldsTooLarge, "too many header lines"
	return false
}
func (r *_httpIn_) HasHeaders() bool {
	return r.hasPairs(r.headerLines, pairHeader)
}
func (r *_httpIn_) AllHeaderLines() (headerLines [][2]string) {
	return r.allPairs(r.headerLines, pairHeader)
}
func (r *_httpIn_) H(name string) string {
	value, _ := r.Header(name)
	return value
}
func (r *_httpIn_) Hstr(name string, defaultValue string) string {
	if value, ok := r.Header(name); ok {
		return value
	}
	return defaultValue
}
func (r *_httpIn_) Hint(name string, defaultValue int) int {
	if value, ok := r.Header(name); ok {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}
func (r *_httpIn_) Header(name string) (value string, ok bool) {
	v, ok := r.getPair(name, 0, r.headerLines, pairHeader)
	return string(v), ok
}
func (r *_httpIn_) RiskyHeader(name string) (value []byte, ok bool) {
	return r.getPair(name, 0, r.headerLines, pairHeader)
}
func (r *_httpIn_) Headers(name string) (values []string, ok bool) {
	return r.getPairs(name, 0, r.headerLines, pairHeader)
}
func (r *_httpIn_) HasHeader(name string) bool {
	_, ok := r.getPair(name, 0, r.headerLines, pairHeader)
	return ok
}
func (r *_httpIn_) DelHeader(name string) (deleted bool) {
	// TODO: add restrictions on what header fields are allowed to del?
	return r.delPair(name, 0, r.headerLines, pairHeader)
}
func (r *_httpIn_) delHeader(name []byte, nameHash uint16) {
	r.delPair(WeakString(name), nameHash, r.headerLines, pairHeader)
}
func (r *_httpIn_) AddHeader(name string, value string) bool { // as extra, by webapp
	// TODO: add restrictions on what header fields are allowed to add? should we check the value?
	// TODO: parse and check? setFlags?
	return r.addExtra(name, value, 0, pairHeader)
}

func (r *_httpIn_) _splitFieldLine(field *pair, fdesc *fdesc, p []byte) bool { // split: #element => [ element ] *( OWS "," OWS [ element ] )
	field.setParsed()

	subField := *field
	subField.setSubField()
	var bakField pair
	numSubs, needComma := 0, false

	for { // each sub value
		haveComma := false
	forComma:
		for subField.value.from < field.value.edge {
			switch b := p[subField.value.from]; b {
			case ' ', '\t':
				subField.value.from++
			case ',':
				haveComma = true
				subField.value.from++
			default:
				break forComma
			}
		}
		if subField.value.from == field.value.edge {
			break
		}
		if needComma && !haveComma {
			r.failReason = "comma needed in multi-value field"
			return false
		}
		subField.value.edge = field.value.edge
		if !r._parseFieldLine(&subField, fdesc, p, false) { // parse one sub field
			// r.failReason is set.
			return false
		}
		if numSubs == 0 { // first sub field, save as backup
			bakField = subField
		} else { // numSubs >= 1, sub fields exist
			if numSubs == 1 { // got the second sub field
				field.setCommaValue() // mark main field as comma-value
				if !r._addExtra(&bakField) {
					r.failReason = "too many extra fields"
					return false
				}
			}
			if !r._addExtra(&subField) {
				r.failReason = "too many sub fields"
				return false
			}
		}
		numSubs++
		subField.value.from = subField.value.edge
		needComma = true
	}
	if numSubs == 1 {
		if bakField.isQuoted() {
			field.setQuoted()
		}
		field.params = bakField.params
		field.dataEdge = bakField.dataEdge
	} else if numSubs == 0 {
		field.dataEdge = field.value.edge
	}
	return true
}
func (r *_httpIn_) _parseFieldLine(field *pair, fdesc *fdesc, p []byte, fully bool) bool { // for field data and value params
	field.setParsed()

	if field.value.isEmpty() {
		if fdesc.allowEmpty {
			field.dataEdge = field.value.edge
			return true
		}
		r.failReason = "field can't be empty"
		return false
	}

	// Now parse field value which is not empty.
	text := field.value
	if p[text.from] != '"' { // field value is normal text
	forData:
		for pSpace := int32(0); text.from < field.value.edge; text.from++ {
			switch b := p[text.from]; b {
			case ' ', '\t':
				if pSpace == 0 {
					pSpace = text.from
				}
			case ';':
				if pSpace == 0 {
					field.dataEdge = text.from
				} else {
					field.dataEdge = pSpace
				}
				break forData
			case ',':
				if !fully {
					field.value.edge = text.from
					field.dataEdge = text.from
					return true
				}
				pSpace = 0
			case '(':
				// TODO: comments can nest
				if fdesc.hasComment {
					text.from++
					for {
						if text.from == field.value.edge {
							r.failReason = "bad comment"
							return false
						}
						if p[text.from] == ')' {
							break
						}
						text.from++
					}
				} else { // comment is not allowed. treat as normal character and reset pSpace
					pSpace = 0
				}
			default: // normal character. reset pSpace
				pSpace = 0
			}
		}
		if text.from == field.value.edge { // exact data
			field.dataEdge = text.from
			return true
		}
	} else { // field value begins with '"'
		text.from++
		for {
			if text.from == field.value.edge { // "...
				field.dataEdge = text.from
				return true
			}
			if p[text.from] == '"' {
				break
			}
			text.from++
		}
		// "..."
		if !fdesc.allowQuote {
			r.failReason = "DQUOTE is not allowed"
			return false
		}
		if text.from-field.value.from == 1 && !fdesc.allowEmpty { // ""
			r.failReason = "field cannot be empty"
			return false
		}
		field.setQuoted()
		field.dataEdge = text.from
		if text.from++; text.from == field.value.edge { // exact "..."
			return true
		}
	afterValue:
		for {
			switch b := p[text.from]; b {
			case ';':
				break afterValue
			case ' ', '\t':
				text.from++
			case ',':
				if fully {
					r.failReason = "comma after dquote"
					return false
				} else {
					field.value.edge = text.from
					return true
				}
			default:
				r.failReason = "malformed DQUOTE and normal text"
				return false
			}
			if text.from == field.value.edge {
				return true
			}
		}
	}
	// text.from is now at ';'
	if !fdesc.allowParam {
		r.failReason = "parameters are not allowed"
		return false
	}

	// Now parse value params.
	field.params.from = uint8(len(r.extras))
	for { // each *( OWS ";" OWS [ token "=" ( token / quoted-string ) ] )
		haveSemic := false
	forSemic:
		for {
			if text.from == field.value.edge {
				return true
			}
			switch b := p[text.from]; b {
			case ' ', '\t':
				text.from++
			case ';':
				haveSemic = true
				text.from++
			case ',':
				if fully {
					r.failReason = "invalid parameter"
					return false
				} else {
					field.value.edge = text.from
					return true
				}
			default:
				break forSemic
			}
		}
		if !haveSemic {
			r.failReason = "semicolon required in parameters"
			return false
		}
		// parameter-name = token
		text.edge = text.from
		for {
			if httpTchar[p[text.edge]] == 0 {
				break
			}
			text.edge++
			if text.edge == field.value.edge {
				r.failReason = "only parameter-name is provided"
				return false
			}
		}
		nameSize := text.edge - text.from
		if nameSize == 0 || nameSize > 255 {
			r.failReason = "parameter-name out of range"
			return false
		}
		if p[text.edge] != '=' {
			r.failReason = "token '=' required"
			return false
		}
		var param pair
		param.nameHash = bytesHash(p[text.from:text.edge])
		param.kind = pairParam
		param.nameSize = uint8(nameSize)
		param.nameFrom = text.from
		param.place = field.place
		// parameter-value = ( token / quoted-string )
		if text.edge++; text.edge == field.value.edge {
			r.failReason = "missing parameter-value"
			return false
		}
		if p[text.edge] == '"' { // quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
			text.edge++
			text.from = text.edge
			for {
				// TODO: detect qdtext
				if text.edge == field.value.edge {
					r.failReason = "invalid quoted-string"
					return false
				}
				if p[text.edge] == '"' {
					break
				}
				text.edge++
			}
			param.value = text
			text.edge++
		} else { // token
			text.from = text.edge
			for text.edge < field.value.edge && httpTchar[p[text.edge]] != 0 {
				text.edge++
			}
			if text.edge == text.from {
				r.failReason = "empty parameter-value is not allowed"
				return false
			}
			param.value = text
		}
		if !r._addExtra(&param) {
			r.failReason = "too many extras"
			return false
		}
		field.params.edge = uint8(len(r.extras))

		text.from = text.edge // for next parameter
	}
}

func (r *_httpIn_) checkContentLength(headerLine *pair, lineIndex uint8) bool { // Content-Length = 1*DIGIT
	// RFC 9110 (section 8.6):
	// Likewise, a sender MUST NOT forward a message with a Content-Length
	// header field value that does not match the ABNF above, with one
	// exception: a recipient of a Content-Length header field value
	// consisting of the same decimal value repeated as a comma-separated
	// list (e.g, "Content-Length: 42, 42") MAY either reject the message as
	// invalid or replace that invalid field value with a single instance of
	// the decimal value, since this likely indicates that a duplicate was
	// generated or combined by an upstream message processor.
	if r.contentSize == -1 { // r.contentSize can only be -1 or >= 0 here. -2 is set after the header section is received if the content is vague
		if size, ok := decToI64(headerLine.valueAt(r.input)); ok {
			r.contentSize = size
			r.iContentLength = lineIndex
			return true
		}
	}
	r.headResult, r.failReason = StatusBadRequest, "bad or duplicate content-length"
	return false
}
func (r *_httpIn_) checkContentLocation(headerLine *pair, lineIndex uint8) bool { // Content-Location = absolute-URI / partial-URI
	if r.iContentLocation == 0 && headerLine.value.notEmpty() {
		// TODO: check syntax
		r.iContentLocation = lineIndex
		return true
	}
	r.headResult, r.failReason = StatusBadRequest, "bad or duplicate content-location"
	return false
}
func (r *_httpIn_) checkContentRange(headerLine *pair, lineIndex uint8) bool { // Content-Range = range-unit SP ( range-resp / unsatisfied-range )
	if r.iContentRange == 0 && headerLine.value.notEmpty() {
		// TODO: check syntax
		r.iContentRange = lineIndex
		return true
	}
	r.headResult, r.failReason = StatusBadRequest, "bad or duplicate content-range"
	return false
}
func (r *_httpIn_) checkContentType(headerLine *pair, lineIndex uint8) bool { // Content-Type = media-type
	// media-type = type "/" subtype *( OWS ";" OWS parameter )
	// type = token
	// subtype = token
	// parameter = token "=" ( token / quoted-string )
	if r.iContentType == 0 && !headerLine.dataEmpty() {
		// TODO: check syntax
		r.iContentType = lineIndex
		return true
	}
	r.headResult, r.failReason = StatusBadRequest, "bad or duplicate content-type"
	return false
}
func (r *_httpIn_) checkDate(headerLine *pair, lineIndex uint8) bool { // Date = HTTP-date
	return r._checkHTTPDate(headerLine, lineIndex, &r.iDate, &r.dateTime)
}
func (r *_httpIn_) _checkHTTPDate(headerLine *pair, lineIndex uint8, pIndex *uint8, toTime *int64) bool { // HTTP-date = day-name "," SP day SP month SP year SP hour ":" minute ":" second SP GMT
	if *pIndex == 0 {
		if httpDate, ok := clockParseHTTPDate(headerLine.valueAt(r.input)); ok {
			*pIndex = lineIndex
			*toTime = httpDate
			return true
		}
	}
	r.headResult, r.failReason = StatusBadRequest, "bad or duplicate http-date"
	return false
}

func (r *_httpIn_) checkAccept(subLines []pair, subFrom uint8, subEdge uint8) bool { // Accept = #( media-range [ weight ] )
	if r.zAccept.isEmpty() {
		r.zAccept.from = subFrom
	}
	r.zAccept.edge = subEdge
	for i := subFrom; i < subEdge; i++ {
		// TODO: check syntax
	}
	return true
}
func (r *_httpIn_) checkAcceptEncoding(subLines []pair, subFrom uint8, subEdge uint8) bool { // Accept-Encoding = #( codings [ weight ] )
	if r.zAcceptEncoding.isEmpty() {
		r.zAcceptEncoding.from = subFrom
	}
	r.zAcceptEncoding.edge = subEdge
	// codings = content-coding / "identity" / "*"
	// content-coding = token
	for i := subFrom; i < subEdge; i++ {
		if r.numAcceptCodings == int8(cap(r.acceptCodings)) {
			break // ignore too many codings
		}
		subLine := &subLines[i]
		if subLine.kind != pairHeader {
			continue
		}
		subData := subLine.dataAt(r.input)
		bytesToLower(subData)
		var coding uint8
		if bytes.Equal(subData, bytesGzip) {
			r.acceptGzip = true
			coding = httpCodingGzip
		} else if bytes.Equal(subData, bytesBrotli) {
			r.acceptBrotli = true
			coding = httpCodingBrotli
		} else if bytes.Equal(subData, bytesDeflate) {
			coding = httpCodingDeflate
		} else if bytes.Equal(subData, bytesCompress) {
			coding = httpCodingCompress
		} else if bytes.Equal(subData, bytesIdentity) {
			coding = httpCodingIdentity
		} else {
			coding = httpCodingUnknown
		}
		r.acceptCodings[r.numAcceptCodings] = coding
		r.numAcceptCodings++
	}
	return true
}
func (r *_httpIn_) checkConnection(subLines []pair, subFrom uint8, subEdge uint8) bool { // Connection = #connection-option
	if r.httpVersion >= Version2 {
		r.headResult, r.failReason = StatusBadRequest, "connection header field is not allowed in HTTP/2 and HTTP/3"
		return false
	}
	if r.zConnection.isEmpty() {
		r.zConnection.from = subFrom
	}
	r.zConnection.edge = subEdge
	// connection-option = token
	for i := subFrom; i < subEdge; i++ {
		subData := subLines[i].dataAt(r.input)
		bytesToLower(subData) // connection options are case-insensitive.
		if bytes.Equal(subData, bytesClose) {
			r.keepAlive = 0
		} else {
			// We don't support "keep-alive" connection option as it's not formal in HTTP/1.0.
		}
	}
	return true
}
func (r *_httpIn_) checkContentEncoding(subLines []pair, subFrom uint8, subEdge uint8) bool { // Content-Encoding = #content-coding
	if r.zContentEncoding.isEmpty() {
		r.zContentEncoding.from = subFrom
	}
	r.zContentEncoding.edge = subEdge
	// content-coding = token
	for i := subFrom; i < subEdge; i++ {
		if r.numContentCodings == int8(cap(r.contentCodings)) {
			r.headResult, r.failReason = StatusBadRequest, "too many content codings applied to content"
			return false
		}
		subData := subLines[i].dataAt(r.input)
		bytesToLower(subData)
		var coding uint8
		if bytes.Equal(subData, bytesGzip) {
			coding = httpCodingGzip
		} else if bytes.Equal(subData, bytesBrotli) {
			coding = httpCodingBrotli
		} else if bytes.Equal(subData, bytesDeflate) { // this is in fact zlib format
			coding = httpCodingDeflate // some non-conformant implementations send the "deflate" compressed data without the zlib wrapper :(
		} else if bytes.Equal(subData, bytesCompress) {
			coding = httpCodingCompress
		} else {
			coding = httpCodingUnknown
		}
		r.contentCodings[r.numContentCodings] = coding
		r.numContentCodings++
	}
	return true
}
func (r *_httpIn_) checkContentLanguage(subLines []pair, subFrom uint8, subEdge uint8) bool { // Content-Language = #language-tag
	if r.zContentLanguage.isEmpty() {
		r.zContentLanguage.from = subFrom
	}
	r.zContentLanguage.edge = subEdge
	for i := subFrom; i < subEdge; i++ {
		// TODO: check syntax
	}
	return true
}
func (r *_httpIn_) checkKeepAlive(subLines []pair, subFrom uint8, subEdge uint8) bool { // Keep-Alive = #keepalive-param
	if r.zKeepAlive.isEmpty() {
		r.zKeepAlive.from = subFrom
	}
	r.zKeepAlive.edge = subEdge
	return true
}
func (r *_httpIn_) checkProxyConnection(subLines []pair, subFrom uint8, subEdge uint8) bool { // Proxy-Connection = #connection-option
	if r.zProxyConnection.isEmpty() {
		r.zProxyConnection.from = subFrom
	}
	r.zProxyConnection.edge = subEdge
	return true
}
func (r *_httpIn_) checkTrailer(subLines []pair, subFrom uint8, subEdge uint8) bool { // Trailer = #field-name
	if r.zTrailer.isEmpty() {
		r.zTrailer.from = subFrom
	}
	r.zTrailer.edge = subEdge
	// field-name = token
	for i := subFrom; i < subEdge; i++ {
		// TODO: check syntax
	}
	return true
}
func (r *_httpIn_) checkTransferEncoding(subLines []pair, subFrom uint8, subEdge uint8) bool { // Transfer-Encoding = #transfer-coding
	if r.httpVersion != Version1_1 {
		r.headResult, r.failReason = StatusBadRequest, "transfer-encoding is only allowed in http/1.1"
		return false
	}
	if r.zTransferEncoding.isEmpty() {
		r.zTransferEncoding.from = subFrom
	}
	r.zTransferEncoding.edge = subEdge
	// transfer-coding = "chunked" / "compress" / "deflate" / "gzip"
	for i := subFrom; i < subEdge; i++ {
		subData := subLines[i].dataAt(r.input)
		bytesToLower(subData)
		if bytes.Equal(subData, bytesChunked) {
			r.transferChunked = true
		} else {
			// RFC 9112 (section 6.1):
			// A server that receives a request message with a transfer coding it does not understand SHOULD respond with 501 (Not Implemented).
			r.headResult, r.failReason = StatusNotImplemented, "unknown transfer coding"
			return false
		}
	}
	return true
}
func (r *_httpIn_) checkVia(subLines []pair, subFrom uint8, subEdge uint8) bool { // Via = #( received-protocol RWS received-by [ RWS comment ] )
	if r.zVia.isEmpty() {
		r.zVia.from = subFrom
	}
	r.zVia.edge = subEdge
	for i := subFrom; i < subEdge; i++ {
		// TODO: check syntax
	}
	return true
}

func (r *_httpIn_) determineContentMode() bool {
	if r.transferChunked { // must be HTTP/1.1 and there is a transfer-encoding: chunked
		if r.contentSize != -1 { // there is also a content-length: nnn
			// RFC 9112 (section 6.3):
			// If a message is received with both a Transfer-Encoding and a Content-Length header field,
			// the Transfer-Encoding overrides the Content-Length. Such a message might indicate an attempt to perform
			// request smuggling (Section 11.2) or response splitting (Section 11.1) and ought to be handled as an error.
			r.headResult, r.failReason = StatusBadRequest, "transfer-encoding conflits with content-length"
			return false
		}
		r.contentSize = -2 // vague
	} else if r.httpVersion >= Version2 && r.contentSize == -1 { // no content-length header field
		// TODO: if there is no content, HTTP/2 and HTTP/3 should mark END_STREAM in fields frame. use this to decide!
		r.contentSize = -2 // if there is no content-length in HTTP/2 or HTTP/3, we treat it as vague
	}
	return true
}
func (r *_httpIn_) IsVague() bool { return r.contentSize == -2 }

func (r *_httpIn_) ContentIsEncoded() bool { return r.zContentEncoding.notEmpty() }
func (r *_httpIn_) ContentSize() int64     { return r.contentSize }
func (r *_httpIn_) ContentType() string    { return string(r.RiskyContentType()) }
func (r *_httpIn_) RiskyContentLength() []byte {
	if r.iContentLength == 0 {
		return nil
	}
	return r.primes[r.iContentLength].valueAt(r.input)
}
func (r *_httpIn_) RiskyContentType() []byte {
	if r.iContentType == 0 {
		return nil
	}
	return r.primes[r.iContentType].dataAt(r.input)
}

func (r *_httpIn_) SetRecvTimeout(timeout time.Duration) { r.recvTimeout = timeout }
func (r *_httpIn_) riskyContent() []byte { // load message content into memory
	r._loadContent()
	if r.stream.isBroken() {
		return nil
	}
	return r.contentText[0:r.receivedSize]
}
func (r *_httpIn_) _loadContent() { // into memory. [0, r.maxContentSize]
	if r.contentReceived {
		// Content is in r.contentText already.
		return
	}
	r.contentReceived = true
	switch content := r._recvContent(true).(type) { // retain
	case []byte: // (0, 64K1]. case happens when sized content <= 64K1
		r.contentText = content // real content is r.contentText[:r.receivedSize]
		r.contentTextKind = httpContentTextPool
	case tempFile: // [0, r.maxContentSize]. case happens when sized content > 64K1, or content is vague.
		contentFile := content.(*os.File)
		if r.receivedSize == 0 { // vague content can has 0 size
			r.contentText = r.input
			r.contentTextKind = httpContentTextInput
		} else { // r.receivedSize > 0
			if r.receivedSize <= _64K1 { // must be vague content because sized content is a []byte if size <= _64K1
				r.contentText = GetNK(r.receivedSize) // 4K/16K/64K1. real content is r.content[:r.receivedSize]
				r.contentTextKind = httpContentTextPool
			} else { // r.receivedSize > 64K1, content can be sized or vague. just alloc
				r.contentText = make([]byte, r.receivedSize)
				r.contentTextKind = httpContentTextMake
			}
			if _, err := io.ReadFull(contentFile, r.contentText[:r.receivedSize]); err != nil {
				// TODO: r.webapp.log
			}
		}
		contentFile.Close()
		if DebugLevel() >= 2 {
			Println("contentFile is left as is, not removed!")
		} else if err := os.Remove(contentFile.Name()); err != nil {
			// TODO: r.webapp.log
		}
	case error: // i/o error or unexpected EOF
		// TODO: log error?
		r.stream.markBroken()
	}
}
func (r *_httpIn_) _dropContent() { // if message content is not received, this will be called at last
	switch content := r._recvContent(false).(type) { // don't retain
	case []byte: // (0, 64K1]. case happens when sized content <= 64K1
		PutNK(content)
	case tempFile: // [0, r.maxContentSize]. case happens when sized content > 64K1, or content is vague.
		if content != fakeFile { // this must not happen!
			BugExitln("temp file is not fake when dropping content")
		}
	case error: // i/o error or unexpected EOF
		// TODO: log error?
		r.stream.markBroken()
	}
}
func (r *_httpIn_) _recvContent(retain bool) any { // to []byte (for small content <= 64K1) or tempFile (for large content > 64K1, or content is vague)
	if r.contentSize > 0 && r.contentSize <= _64K1 { // (0, 64K1]. save to []byte.
		if err := r.stream.setReadDeadline(); err != nil { // the whole content is small so must be received in one read timeout. for all http versions!
			return err
		}
		// Since content is small, r.bodyWindow and tempFile are not needed.
		contentText := GetNK(r.contentSize) // 4K/16K/64K1. max size of content is 64K1
		r.receivedSize = int64(r.imme.size())
		if r.receivedSize > 0 { // r.imme has data
			copy(contentText, r.input[r.imme.from:r.imme.edge])
			r.imme.zero()
		}
		if n, err := r.stream.readFull(contentText[r.receivedSize:r.contentSize]); err == nil {
			r.receivedSize += int64(n)
			return contentText // []byte, fetched from pool
		} else {
			PutNK(contentText)
			return err
		}
	} else { // (64K1, r.maxContentSize] when sized, or [0, r.maxContentSize] when vague. save to tempFile and return the file
		contentFile, err := r._newTempFile(retain)
		if err != nil {
			return err
		}
		var data []byte
		for {
			data, err = r.in.readContent() // read timeout is set inside readContent()
			if len(data) > 0 {             // skip 0, nothing to write
				if _, e := contentFile.Write(data); e != nil {
					err = e
					goto badRead
				}
			}
			if err == io.EOF {
				break
			} else if err != nil {
				goto badRead
			}
		}
		if _, err = contentFile.Seek(0, 0); err != nil {
			goto badRead
		}
		return contentFile // the tempFile
	badRead:
		contentFile.Close()
		if retain { // the tempFile is not fake, so must remove.
			os.Remove(contentFile.Name())
		}
		return err
	}
}

func (r *_httpIn_) addTrailerLine(trailerLine *pair) bool { // as prime
	if edge, ok := r._addPrime(trailerLine); ok {
		r.trailerLines.edge = edge
		return true
	}
	r.bodyResult, r.failReason = StatusRequestHeaderFieldsTooLarge, "too many trailer lines"
	return false
}
func (r *_httpIn_) HasTrailers() bool {
	return r.hasPairs(r.trailerLines, pairTrailer)
}
func (r *_httpIn_) AllTrailerLines() (trailerLines [][2]string) {
	return r.allPairs(r.trailerLines, pairTrailer)
}
func (r *_httpIn_) T(name string) string {
	value, _ := r.Trailer(name)
	return value
}
func (r *_httpIn_) Tstr(name string, defaultValue string) string {
	if value, ok := r.Trailer(name); ok {
		return value
	}
	return defaultValue
}
func (r *_httpIn_) Tint(name string, defaultValue int) int {
	if value, ok := r.Trailer(name); ok {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}
func (r *_httpIn_) Trailer(name string) (value string, ok bool) {
	v, ok := r.getPair(name, 0, r.trailerLines, pairTrailer)
	return string(v), ok
}
func (r *_httpIn_) RiskyTrailer(name string) (value []byte, ok bool) {
	return r.getPair(name, 0, r.trailerLines, pairTrailer)
}
func (r *_httpIn_) Trailers(name string) (values []string, ok bool) {
	return r.getPairs(name, 0, r.trailerLines, pairTrailer)
}
func (r *_httpIn_) HasTrailer(name string) bool {
	_, ok := r.getPair(name, 0, r.trailerLines, pairTrailer)
	return ok
}
func (r *_httpIn_) DelTrailer(name string) (deleted bool) {
	return r.delPair(name, 0, r.trailerLines, pairTrailer)
}
func (r *_httpIn_) delTrailer(name []byte, nameHash uint16) {
	r.delPair(WeakString(name), nameHash, r.trailerLines, pairTrailer)
}
func (r *_httpIn_) AddTrailer(name string, value string) bool { // as extra, by webapp
	// TODO: add restrictions on what trailer fields are allowed to add? should we check the value?
	// TODO: parse and check? setFlags?
	return r.addExtra(name, value, 0, pairTrailer)
}

func (r *_httpIn_) _addPrime(prime *pair) (edge uint8, ok bool) {
	if len(r.primes) == cap(r.primes) { // full
		if cap(r.primes) != cap(r.stockPrimes) { // too many primes
			return 0, false
		}
		if DebugLevel() >= 2 {
			Println("use large primes!")
		}
		r.primes = getPairs()
		r.primes = append(r.primes, r.stockPrimes[:]...)
	}
	r.primes = append(r.primes, *prime)
	return uint8(len(r.primes)), true
}
func (r *_httpIn_) _delPrime(i uint8) { r.primes[i].zero() }

func (r *_httpIn_) addExtra(name string, value string, nameHash uint16, extraKind int8) bool {
	nameSize := len(name)
	if nameSize == 0 || nameSize > 255 { // name size is limited at 255
		return false
	}
	valueSize := len(value)
	if extraKind == pairForm { // for forms, max value size is 1G
		if valueSize > _1G {
			return false
		}
	} else if valueSize > _16K { // for non-forms, max value size is 16K
		return false
	}
	if !r._growArray(int32(nameSize + valueSize)) { // extras are always placed in r.array
		return false
	}
	extra := &r.mainPair
	extra.zero()
	if nameHash == 0 {
		extra.nameHash = stringHash(name)
	} else {
		extra.nameHash = nameHash
	}
	extra.kind = extraKind
	extra.place = placeArray
	extra.nameFrom = r.arrayEdge
	extra.nameSize = uint8(nameSize)
	r.arrayEdge += int32(copy(r.array[r.arrayEdge:], name))
	extra.value.from = r.arrayEdge
	r.arrayEdge += int32(copy(r.array[r.arrayEdge:], value))
	extra.value.edge = r.arrayEdge
	return r._addExtra(extra)
}
func (r *_httpIn_) _addExtra(extra *pair) bool {
	if len(r.extras) == cap(r.extras) { // full
		if cap(r.extras) != cap(r.stockExtras) { // too many extras
			return false
		}
		if DebugLevel() >= 2 {
			Println("use large extras!")
		}
		r.extras = getPairs()
		r.extras = append(r.extras, r.stockExtras[:]...)
	}
	r.extras = append(r.extras, *extra)
	r.hasExtra[extra.kind] = true
	return true
}

func (r *_httpIn_) hasPairs(primes zone, extraKind int8) bool {
	return primes.notEmpty() || r.hasExtra[extraKind]
}
func (r *_httpIn_) allPairs(primes zone, extraKind int8) [][2]string {
	var pairs [][2]string
	if extraKind == pairHeader || extraKind == pairTrailer { // skip sub field lines, only collects values of main field lines
		for i := primes.from; i < primes.edge; i++ {
			if prime := &r.primes[i]; prime.nameHash != 0 {
				p := r._placeOf(prime)
				pairs = append(pairs, [2]string{string(prime.nameAt(p)), string(prime.valueAt(p))})
			}
		}
		if r.hasExtra[extraKind] {
			for i := range len(r.extras) {
				if extra := &r.extras[i]; extra.nameHash != 0 && extra.kind == extraKind && !extra.isSubField() {
					pairs = append(pairs, [2]string{string(extra.nameAt(r.array)), string(extra.valueAt(r.array))})
				}
			}
		}
	} else { // queries, cookies, forms, and params
		for i := primes.from; i < primes.edge; i++ {
			if prime := &r.primes[i]; prime.nameHash != 0 {
				p := r._placeOf(prime)
				pairs = append(pairs, [2]string{string(prime.nameAt(p)), string(prime.valueAt(p))})
			}
		}
		if r.hasExtra[extraKind] {
			for i := range len(r.extras) {
				if extra := &r.extras[i]; extra.nameHash != 0 && extra.kind == extraKind {
					pairs = append(pairs, [2]string{string(extra.nameAt(r.array)), string(extra.valueAt(r.array))})
				}
			}
		}
	}
	return pairs
}
func (r *_httpIn_) getPair(name string, nameHash uint16, primes zone, extraKind int8) (value []byte, ok bool) {
	if name == "" {
		return
	}
	if nameHash == 0 {
		nameHash = stringHash(name)
	}
	if extraKind == pairHeader || extraKind == pairTrailer { // skip comma field lines, only collects data of field lines without comma
		for i := primes.from; i < primes.edge; i++ {
			if prime := &r.primes[i]; prime.nameHash == nameHash {
				if p := r._placeOf(prime); prime.nameEqualString(p, name) {
					if !prime.isParsed() && !r._splitFieldLine(prime, defaultFdesc, p) {
						continue
					}
					if !prime.isCommaValue() { // not a comma field, collect it
						return prime.dataAt(p), true
					}
				}
			}
		}
		if r.hasExtra[extraKind] {
			for i := range len(r.extras) {
				if extra := &r.extras[i]; extra.nameHash == nameHash && extra.kind == extraKind && !extra.isCommaValue() { // not a comma field, collect it
					if p := r._placeOf(extra); extra.nameEqualString(p, name) {
						return extra.dataAt(p), true
					}
				}
			}
		}
	} else { // queries, cookies, forms, and params
		for i := primes.from; i < primes.edge; i++ {
			if prime := &r.primes[i]; prime.nameHash == nameHash {
				if p := r._placeOf(prime); prime.nameEqualString(p, name) {
					return prime.valueAt(p), true
				}
			}
		}
		if r.hasExtra[extraKind] {
			for i := range len(r.extras) {
				if extra := &r.extras[i]; extra.nameHash == nameHash && extra.kind == extraKind && extra.nameEqualString(r.array, name) {
					return extra.valueAt(r.array), true
				}
			}
		}
	}
	return
}
func (r *_httpIn_) getPairs(name string, nameHash uint16, primes zone, extraKind int8) (values []string, ok bool) {
	if name == "" {
		return
	}
	if nameHash == 0 {
		nameHash = stringHash(name)
	}
	if extraKind == pairHeader || extraKind == pairTrailer { // skip comma field lines, only collects data of field lines without comma
		for i := primes.from; i < primes.edge; i++ {
			if prime := &r.primes[i]; prime.nameHash == nameHash {
				if p := r._placeOf(prime); prime.nameEqualString(p, name) {
					if !prime.isParsed() && !r._splitFieldLine(prime, defaultFdesc, p) {
						continue
					}
					if !prime.isCommaValue() { // not a comma field, collect it
						values = append(values, string(prime.dataAt(p)))
					}
				}
			}
		}
		if r.hasExtra[extraKind] {
			for i := range len(r.extras) {
				if extra := &r.extras[i]; extra.nameHash == nameHash && extra.kind == extraKind && !extra.isCommaValue() { // not a comma field, collect it
					if p := r._placeOf(extra); extra.nameEqualString(p, name) {
						values = append(values, string(extra.dataAt(p)))
					}
				}
			}
		}
	} else { // queries, cookies, forms, and params
		for i := primes.from; i < primes.edge; i++ {
			if prime := &r.primes[i]; prime.nameHash == nameHash {
				if p := r._placeOf(prime); prime.nameEqualString(p, name) {
					values = append(values, string(prime.valueAt(p)))
				}
			}
		}
		if r.hasExtra[extraKind] {
			for i := range len(r.extras) {
				if extra := &r.extras[i]; extra.nameHash == nameHash && extra.kind == extraKind && extra.nameEqualString(r.array, name) {
					values = append(values, string(extra.valueAt(r.array)))
				}
			}
		}
	}
	if len(values) > 0 {
		ok = true
	}
	return
}
func (r *_httpIn_) delPair(name string, nameHash uint16, primes zone, extraKind int8) (deleted bool) {
	if name == "" {
		return
	}
	if nameHash == 0 {
		nameHash = stringHash(name)
	}
	for i := primes.from; i < primes.edge; i++ {
		if prime := &r.primes[i]; prime.nameHash == nameHash {
			if p := r._placeOf(prime); prime.nameEqualString(p, name) {
				prime.zero()
				deleted = true
			}
		}
	}
	if r.hasExtra[extraKind] {
		for i := range len(r.extras) {
			if extra := &r.extras[i]; extra.nameHash == nameHash && extra.kind == extraKind && extra.nameEqualString(r.array, name) {
				extra.zero()
				deleted = true
			}
		}
	}
	return
}
func (r *_httpIn_) _placeOf(pair *pair) []byte {
	var place []byte
	switch pair.place {
	case placeInput:
		place = r.input
	case placeArray:
		place = r.array
	case placeStatic2:
		place = hpackStaticBytes
	case placeStatic3:
		place = qpackStaticBytes
	default:
		BugExitln("unknown pair.place")
	}
	return place
}

func (r *_httpIn_) proxyTakeContent() any {
	if r.contentReceived {
		if r.contentFile == nil {
			return r.contentText // immediate
		}
		return r.contentFile
	}
	r.contentReceived = true
	switch content := r._recvContent(true).(type) { // retain
	case []byte: // (0, 64K1]. case happens when sized content <= 64K1
		r.contentText = content
		r.contentTextKind = httpContentTextPool // so r.contentText can be freed on end
		return r.contentText[0:r.receivedSize]
	case tempFile: // [0, r.maxContentSize]. case happens when sized content > 64K1, or content is vague.
		r.contentFile = content.(*os.File)
		return r.contentFile
	case error: // i/o error or unexpected EOF
		// TODO: log err?
	}
	r.stream.markBroken()
	return nil
}

func (r *_httpIn_) proxyDelHopHeaderFields() {
	r._proxyDelHopFieldLines(r.headerLines, pairHeader)
}
func (r *_httpIn_) proxyDelHopTrailerFields() {
	r._proxyDelHopFieldLines(r.trailerLines, pairTrailer)
}
func (r *_httpIn_) _proxyDelHopFieldLines(fieldLines zone, extraKind int8) { // TODO: improve performance
	delField := r.delHeader
	if extraKind == pairTrailer {
		delField = r.delTrailer
	}
	// These fields should be removed anyway: proxy-connection, keep-alive, te, transfer-encoding, upgrade
	if r.zProxyConnection.notEmpty() {
		delField(bytesProxyConnection, hashProxyConnection)
	}
	if r.zKeepAlive.notEmpty() {
		delField(bytesKeepAlive, hashKeepAlive)
	}
	if r.zTransferEncoding.notEmpty() {
		delField(bytesTransferEncoding, hashTransferEncoding)
	}
	if r.zUpgrade.notEmpty() {
		delField(bytesUpgrade, hashUpgrade)
	}
	r.in.proxyDelHopFieldLines(extraKind) // don't pass delField as parameter, it causes delField escapes to heap

	// Now remove connection options in primes and extras.
	// Note: we don't remove ("connection: xxx, yyy") itself here, we simply restrict it from being copied or inserted when acting as a proxy.
	for i := r.zConnection.from; i < r.zConnection.edge; i++ {
		prime := &r.primes[i]
		// Skip fields that are not "connection: xxx, yyy"
		if prime.nameHash != hashConnection || !prime.nameEqualBytes(r.input, bytesConnection) {
			continue
		}
		p := r._placeOf(prime)
		optionName := prime.dataAt(p)
		optionHash := bytesHash(optionName)
		// Skip options that are "connection: connection"
		if optionHash == hashConnection && bytes.Equal(optionName, bytesConnection) {
			continue
		}
		// Got a "connection: xxx" option, remove it from fields
		for j := fieldLines.from; j < fieldLines.edge; j++ {
			if fieldLine := &r.primes[j]; fieldLine.nameHash == optionHash && fieldLine.nameEqualBytes(p, optionName) {
				fieldLine.zero()
			}
		}
		if r.hasExtra[extraKind] {
			for j := range len(r.extras) {
				if extra := &r.extras[j]; extra.nameHash == optionHash && extra.kind == extraKind {
					if p := r._placeOf(extra); extra.nameEqualBytes(p, optionName) {
						extra.zero()
					}
				}
			}
		}
	}
}

func (r *_httpIn_) proxyWalkHeaderLines(out httpOut, callback func(out httpOut, headerLine *pair, headerName []byte, lineValue []byte) bool) bool { // excluding sub header lines
	return r._proxyWalkMainFields(r.headerLines, pairHeader, out, callback)
}
func (r *_httpIn_) proxyWalkTrailerLines(out httpOut, callback func(out httpOut, trailerLine *pair, trailerName []byte, lineValue []byte) bool) bool { // excluding sub trailer lines
	return r._proxyWalkMainFields(r.trailerLines, pairTrailer, out, callback)
}
func (r *_httpIn_) _proxyWalkMainFields(fieldLines zone, extraKind int8, out httpOut, callback func(out httpOut, fieldLine *pair, fieldName []byte, lineValue []byte) bool) bool {
	for i := fieldLines.from; i < fieldLines.edge; i++ {
		if fieldLine := &r.primes[i]; fieldLine.nameHash != 0 {
			p := r._placeOf(fieldLine)
			if !callback(out, fieldLine, fieldLine.nameAt(p), fieldLine.valueAt(p)) {
				return false
			}
		}
	}
	if r.hasExtra[extraKind] {
		for i := range len(r.extras) {
			if field := &r.extras[i]; field.nameHash != 0 && field.kind == extraKind && !field.isSubField() {
				if !callback(out, field, field.nameAt(r.array), field.valueAt(r.array)) {
					return false
				}
			}
		}
	}
	return true
}

func (r *_httpIn_) arrayCopy(src []byte) bool { // callers don't guarantee the intended memory cost is limited
	if len(src) > 0 {
		edge := r.arrayEdge + int32(len(src))
		if edge < r.arrayEdge { // overflow
			return false
		}
		if edge > r.maxMemoryContentSize {
			return false
		}
		if !r._growArray(int32(len(src))) {
			return false
		}
		r.arrayEdge += int32(copy(r.array[r.arrayEdge:], src))
	}
	return true
}
func (r *_httpIn_) arrayPush(b byte) { // callers must ensure the intended memory cost is limited
	r.array[r.arrayEdge] = b
	if r.arrayEdge++; r.arrayEdge == int32(cap(r.array)) {
		r._growArray(1)
	}
}
func (r *_httpIn_) _growArray(size int32) bool { // stock(<4K)->4K->16K->64K1->(128K->...->1G)
	edge := r.arrayEdge + size
	if edge < 0 || edge > _1G { // cannot overflow hard limit: 1G
		return false
	}
	if edge <= int32(cap(r.array)) { // existing array is enough
		return true
	}
	lastKind := r.arrayKind
	var array []byte
	if edge <= _64K1 { // (stock, 64K1]
		r.arrayKind = arrayKindPool
		array = GetNK(int64(edge)) // 4K/16K/64K1
	} else { // > _64K1
		r.arrayKind = arrayKindMake
		if edge <= _128K {
			array = make([]byte, _128K)
		} else if edge <= _256K {
			array = make([]byte, _256K)
		} else if edge <= _512K {
			array = make([]byte, _512K)
		} else if edge <= _1M {
			array = make([]byte, _1M)
		} else if edge <= _2M {
			array = make([]byte, _2M)
		} else if edge <= _4M {
			array = make([]byte, _4M)
		} else if edge <= _8M {
			array = make([]byte, _8M)
		} else if edge <= _16M {
			array = make([]byte, _16M)
		} else if edge <= _32M {
			array = make([]byte, _32M)
		} else if edge <= _64M {
			array = make([]byte, _64M)
		} else if edge <= _128M {
			array = make([]byte, _128M)
		} else if edge <= _256M {
			array = make([]byte, _256M)
		} else if edge <= _512M {
			array = make([]byte, _512M)
		} else { // <= _1G
			array = make([]byte, _1G)
		}
	}
	copy(array, r.array[0:r.arrayEdge])
	if lastKind == arrayKindPool {
		PutNK(r.array)
	}
	r.array = array
	return true
}

func (r *_httpIn_) saveContentFilesDir() string { return r.stream.Holder().SaveContentFilesDir() }

func (r *_httpIn_) _newTempFile(retain bool) (tempFile, error) { // to save content to
	if retain {
		filesDir := r.saveContentFilesDir()
		pathBuffer := r.RiskyMake(len(filesDir) + 19) // 19 bytes is enough for an int64
		n := copy(pathBuffer, filesDir)
		n += r.stream.MakeTempName(pathBuffer[n:], time.Now().Unix())
		return os.OpenFile(string(pathBuffer[:n]), os.O_RDWR|os.O_CREATE, 0644)
	} else { // since data is not used by upper caller, we don't need to actually write data to file.
		return fakeFile, nil
	}
}

func (r *_httpIn_) _isLongTime() bool { // reports whether the receiving of incoming content costs a long time
	return r.recvTimeout > 0 && time.Since(r.bodyTime) >= r.recvTimeout
}

var ( // _httpIn_ errors
	httpInBadChunk = errors.New("bad incoming http chunk")
	httpInLongTime = errors.New("http incoming costs a long time")
)

// httpOut
type httpOut interface {
	controlData() []byte
	addHeader(name []byte, value []byte) bool
	header(name []byte) (value []byte, ok bool)
	hasHeader(name []byte) bool
	delHeader(name []byte) (deleted bool)
	delHeaderAt(i uint8)
	insertHeader(nameHash uint16, name []byte, value []byte) bool
	removeHeader(nameHash uint16, name []byte) (deleted bool)
	addedHeaders() []byte
	fixedHeaders() []byte
	finalizeHeaders()
	beforeSend()
	doSend() error
	sendChain() error // content
	beforeEcho()
	echoHeaders() error
	doEcho() error
	echoChain() error // chunks
	addTrailer(name []byte, value []byte) bool
	trailer(name []byte) (value []byte, ok bool)
	finalizeVague() error
	proxyPassHeaders() error
	proxyPassBytes(data []byte) error
}

// _httpOut_ is a mixin.
type _httpOut_ struct { // for backendRequest_ and serverResponse_. outgoing message, needs building
	// Assocs
	stream httpStream // *backend[1-3]Stream, *server[1-3]Stream
	out    httpOut    // *backend[1-3]Request, *server[1-3]Response
	// Stream states (stocks)
	stockOutput [1536]byte // for r.output
	// Stream states (controlled)
	edges [128]uint16 // edges of header fields or trailer fields in r.output, but not used at the same time. controlled by r.numHeaderFields or r.numTrailerFields. edges[0] is not used!
	piece Piece       // for r.chain. used when sending content or echoing chunks
	chain Chain       // outgoing piece chain. used when sending content or echoing chunks
	// Stream states (non-zeros)
	output           []byte        // bytes of the outgoing header fields or trailer fields which are not manipulated at the same time. [<r.stockOutput>/4K/16K]
	sendTimeout      time.Duration // timeout to send the whole message. zero means no timeout
	contentSize      int64         // info of outgoing content. -1: not set, -2: vague, >=0: size
	httpVersion      uint8         // Version1_1, Version2, Version3
	asRequest        bool          // treat this outgoing message as request?
	numHeaderFields  uint8         // 1+num of added header fields, starts from 1 because edges[0] is not used
	numTrailerFields uint8         // 1+num of added trailer fields, starts from 1 because edges[0] is not used
	// Stream states (zeros)
	sendTime      time.Time   // the time when first write operation is performed
	contentRanges []Range     // if outgoing content is ranged, this will be set
	rangeType     string      // if outgoing content is ranged, this will be the content type for each range
	vector        net.Buffers // for writeVec. to overcome the limitation of Go's escape analysis. set when used, reset after stream
	fixedVector   [4][]byte   // for sending/echoing message. reset after stream
	_httpOut0                 // all values in this struct must be zero by default!
}
type _httpOut0 struct { // for fast reset, entirely
	controlEdge   uint16 // edge of control in r.output. only used by request to mark the method and request-target
	outputEdge    uint16 // edge of r.output. max size of r.output must be <= 16K. used by both header fields and trailer fields because they are not manipulated at the same time
	hasRevisers   bool   // are there any outgoing revisers hooked on this outgoing message?
	isSent        bool   // whether the message is sent
	forbidContent bool   // forbid content?
	forbidFraming bool   // forbid content-length and transfer-encoding?
	iContentType  uint8  // position of content-type in r.edges
	iDate         uint8  // position of date in r.edges
}

func (r *_httpOut_) onUse(httpVersion uint8, asRequest bool) { // for non-zeros
	r.output = r.stockOutput[:]
	holder := r.stream.Holder()
	r.sendTimeout = holder.SendTimeout()
	r.contentSize = -1 // not set
	r.httpVersion = httpVersion
	r.asRequest = asRequest
	r.numHeaderFields, r.numTrailerFields = 1, 1 // r.edges[0] is not used
}
func (r *_httpOut_) onEnd() { // for zeros
	if cap(r.output) != cap(r.stockOutput) {
		PutNK(r.output)
		r.output = nil
	}
	// r.piece was reset in echo(), and will be reset here if send() was used. double free doesn't matter
	r.chain.free()

	r.sendTime = time.Time{}
	r.contentRanges = nil
	r.rangeType = ""
	r.vector = nil
	r.fixedVector = [4][]byte{}
	r._httpOut0 = _httpOut0{}
}

func (r *_httpOut_) riskyMake(size int) []byte { return r.stream.riskyMake(size) }

func (r *_httpOut_) AddContentType(contentType string) bool {
	return r.AddHeaderBytes(bytesContentType, ConstBytes(contentType))
}
func (r *_httpOut_) AddContentTypeBytes(contentType []byte) bool {
	return r.AddHeaderBytes(bytesContentType, contentType)
}

func (r *_httpOut_) Header(name string) (value string, ok bool) {
	v, ok := r.out.header(ConstBytes(name))
	return string(v), ok
}
func (r *_httpOut_) HasHeader(name string) bool {
	return r.out.hasHeader(ConstBytes(name))
}
func (r *_httpOut_) AddHeader(name string, value string) bool {
	return r.AddHeaderBytes(ConstBytes(name), ConstBytes(value))
}
func (r *_httpOut_) AddHeaderBytes(name []byte, value []byte) bool {
	nameHash, valid, lowerName := r._nameCheck(name)
	if !valid {
		return false
	}
	for _, b := range value { // to prevent response splitting
		if b == '\r' || b == '\n' {
			return false
		}
	}
	return r.out.insertHeader(nameHash, lowerName, value) // some header fields (e.g. "connection") are restricted
}
func (r *_httpOut_) DelHeader(name string) bool {
	return r.DelHeaderBytes(ConstBytes(name))
}
func (r *_httpOut_) DelHeaderBytes(name []byte) bool {
	nameHash, valid, lowerName := r._nameCheck(name)
	if !valid {
		return false
	}
	return r.out.removeHeader(nameHash, lowerName)
}
func (r *_httpOut_) _nameCheck(fieldName []byte) (nameHash uint16, valid bool, lowerName []byte) { // TODO: improve performance
	nameSize := len(fieldName)
	if nameSize == 0 || nameSize > 255 {
		return 0, false, nil
	}
	allLower := true
	for i := range nameSize {
		if b := fieldName[i]; b >= 'a' && b <= 'z' || b == '-' {
			nameHash += uint16(b)
		} else {
			nameHash = 0
			allLower = false
			break
		}
	}
	if allLower {
		return nameHash, true, fieldName
	}
	nameBuffer := r.stream.buffer256() // enough for name
	for i := range nameSize {
		b := fieldName[i]
		if b >= 'A' && b <= 'Z' {
			b += 0x20 // to lower
		} else if !(b >= 'a' && b <= 'z' || b == '-') {
			return 0, false, nil
		}
		nameHash += uint16(b)
		nameBuffer[i] = b
	}
	return nameHash, true, nameBuffer[:nameSize]
}

func (r *_httpOut_) isVague() bool { return r.contentSize == -2 }
func (r *_httpOut_) IsSent() bool  { return r.isSent }

func (r *_httpOut_) _insertContentType(contentType []byte) (ok bool) {
	return r._appendSingleton(&r.iContentType, bytesContentType, contentType)
}
func (r *_httpOut_) _insertDate(date []byte) (ok bool) { // rarely used in backend request
	return r._appendSingleton(&r.iDate, bytesDate, date)
}
func (r *_httpOut_) _appendSingleton(pIndex *uint8, name []byte, value []byte) bool {
	if *pIndex > 0 || !r.out.addHeader(name, value) {
		return false
	}
	*pIndex = r.numHeaderFields - 1 // r.numHeaderFields begins from 1, so must minus one
	return true
}

func (r *_httpOut_) _removeContentType() (deleted bool) { return r._deleteSingleton(&r.iContentType) }
func (r *_httpOut_) _removeDate() (deleted bool)        { return r._deleteSingleton(&r.iDate) }
func (r *_httpOut_) _deleteSingleton(pIndex *uint8) bool {
	if *pIndex == 0 { // not exist
		return false
	}
	r.out.delHeaderAt(*pIndex)
	*pIndex = 0
	return true
}

func (r *_httpOut_) _setUnixTime(pUnixTime *int64, pIndex *uint8, unixTime int64) bool {
	if unixTime < 0 {
		return false
	}
	if *pUnixTime == -2 { // was set through general api, must delete it
		r.out.delHeaderAt(*pIndex)
		*pIndex = 0
	}
	*pUnixTime = unixTime
	return true
}
func (r *_httpOut_) _addUnixTime(pUnixTime *int64, pIndex *uint8, name []byte, httpDate []byte) bool {
	if *pUnixTime == -2 { // was set through general api, must delete it
		r.out.delHeaderAt(*pIndex)
		*pIndex = 0
	} else { // >= 0 or -1
		*pUnixTime = -2
	}
	if !r.out.addHeader(name, httpDate) {
		return false
	}
	*pIndex = r.numHeaderFields - 1 // r.numHeaderFields begins from 1, so must minus one
	return true
}
func (r *_httpOut_) _delUnixTime(pUnixTime *int64, pIndex *uint8) bool {
	if *pUnixTime == -1 {
		return false
	}
	if *pUnixTime == -2 { // was set through general api, must delete it
		r.out.delHeaderAt(*pIndex)
		*pIndex = 0
	}
	*pUnixTime = -1
	return true
}

func (r *_httpOut_) pickOutRanges(contentRanges []Range, rangeType string) {
	r.contentRanges = contentRanges
	r.rangeType = rangeType
}

func (r *_httpOut_) SetSendTimeout(timeout time.Duration) { r.sendTimeout = timeout }

func (r *_httpOut_) Send(content string) error      { return r.sendText(ConstBytes(content)) }
func (r *_httpOut_) SendBytes(content []byte) error { return r.sendText(content) }
func (r *_httpOut_) SendFile(contentPath string) error {
	file, err := os.Open(contentPath)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	return r.sendFile(file, info, true) // true to close on end
}
func (r *_httpOut_) SendJSON(content any) error { // TODO: optimize performance
	r.AddContentTypeBytes(bytesTypeJSON)
	data, err := json.Marshal(content)
	if err != nil {
		return err
	}
	return r.sendText(data)
}

func (r *_httpOut_) Echo(chunk string) error      { return r.echoText(ConstBytes(chunk)) }
func (r *_httpOut_) EchoBytes(chunk []byte) error { return r.echoText(chunk) }
func (r *_httpOut_) EchoFile(chunkPath string) error {
	file, err := os.Open(chunkPath)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	return r.echoFile(file, info, true) // true to close on end
}
func (r *_httpOut_) AddTrailer(name string, value string) bool {
	return r.AddTrailerBytes(ConstBytes(name), ConstBytes(value))
}
func (r *_httpOut_) AddTrailerBytes(name []byte, value []byte) bool {
	if !r.isSent { // trailer fields must be added after header fields & content was sent, otherwise r.output will be messed up
		return false
	}
	return r.out.addTrailer(name, value)
}
func (r *_httpOut_) Trailer(name string) (value string, ok bool) {
	v, ok := r.out.trailer(ConstBytes(name))
	return string(v), ok
}

func (r *_httpOut_) _proxyPassMessage(in httpIn) error {
	proxyPass := r.out.proxyPassBytes
	if in.IsVague() || r.hasRevisers { // if we need to revise, we always use vague no matter the original content is sized or vague
		proxyPass = r.EchoBytes
	} else { // in is sized and there are no revisers, use proxyPassBytes
		r.isSent = true
		r.contentSize = in.ContentSize()
		// TODO: find a way to reduce i/o syscalls if content is small?
		if err := r.out.proxyPassHeaders(); err != nil {
			return err
		}
	}
	for {
		data, err := in.readContent() // read timeout is set inside readContent()
		if len(data) >= 0 {
			if e := proxyPass(data); e != nil {
				return e
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	if in.HasTrailers() {
		if !in.proxyWalkTrailerLines(r.out, func(out httpOut, trailerLine *pair, trailerName []byte, lineValue []byte) bool {
			return out.addTrailer(trailerName, lineValue) // added trailer fields will be written by upper code eventually.
		}) {
			return httpOutTrailerFailed
		}
	}
	return nil
}
func (r *_httpOut_) proxyPostMessage(content any, hasTrailers bool) error {
	if contentText, ok := content.([]byte); ok {
		if hasTrailers { // if (in the future) we supports taking vague content in buffer, this happens
			return r.echoText(contentText)
		} else {
			return r.sendText(contentText)
		}
	} else if contentFile, ok := content.(*os.File); ok {
		fileInfo, err := contentFile.Stat()
		if err != nil {
			contentFile.Close()
			return err
		}
		if hasTrailers { // we must use vague
			return r.echoFile(contentFile, fileInfo, false) // false means don't close on end. this file doesn't belong to r
		} else {
			return r.sendFile(contentFile, fileInfo, false) // false means don't close on end. this file doesn't belong to r
		}
	} else { // nil means no content.
		if err := r._beforeSend(); err != nil {
			return err
		}
		r.forbidContent = true
		return r.out.doSend()
	}
}

func (r *_httpOut_) sendText(content []byte) error {
	if err := r._beforeSend(); err != nil {
		return err
	}
	r.piece.SetText(content)
	r.chain.PushTail(&r.piece)
	r.contentSize = int64(len(content)) // initial size, may be changed by revisers
	return r.out.doSend()
}
func (r *_httpOut_) sendFile(content *os.File, info os.FileInfo, shut bool) error {
	if err := r._beforeSend(); err != nil {
		return err
	}
	r.piece.SetFile(content, info, shut)
	r.chain.PushTail(&r.piece)
	r.contentSize = info.Size() // initial size, may be changed by revisers
	return r.out.doSend()
}
func (r *_httpOut_) _beforeSend() error {
	if r.isSent {
		return httpOutAlreadySent
	}
	r.isSent = true
	if r.hasRevisers {
		r.out.beforeSend()
	}
	return nil
}

func (r *_httpOut_) echoText(chunk []byte) error {
	if err := r._beforeEcho(); err != nil {
		return err
	}
	if len(chunk) == 0 { // empty chunk is not actually sent, since it is used to indicate the end. pretend to succeed
		return nil
	}
	r.piece.SetText(chunk)
	defer r.piece.zero()
	return r.out.doEcho()
}
func (r *_httpOut_) echoFile(chunk *os.File, info os.FileInfo, shut bool) error {
	if err := r._beforeEcho(); err != nil {
		return err
	}
	if info.Size() == 0 { // empty chunk is not actually sent, since it is used to indicate the end. pretend to succeed
		if shut {
			chunk.Close()
		}
		return nil
	}
	r.piece.SetFile(chunk, info, shut)
	defer r.piece.zero()
	return r.out.doEcho()
}
func (r *_httpOut_) _beforeEcho() error {
	if r.stream.isBroken() {
		return httpOutWriteBroken
	}
	if r.isSent {
		return nil
	}
	if r.contentSize != -1 { // is set, either sized or vague
		return httpOutMixedContent
	}
	r.isSent = true
	r.contentSize = -2 // vague
	if r.hasRevisers {
		r.out.beforeEcho()
	}
	return r.out.echoHeaders()
}

func (r *_httpOut_) growHeaders(size int) (from int, edge int, ok bool) { // header fields and trailer fields are not manipulated at the same time
	if r.numHeaderFields == uint8(cap(r.edges)) { // too many header fields
		return
	}
	return r._growFields(size)
}
func (r *_httpOut_) growTrailers(size int) (from int, edge int, ok bool) { // header fields and trailer fields are not manipulated at the same time
	if r.numTrailerFields == uint8(cap(r.edges)) { // too many trailer fields
		return
	}
	return r._growFields(size)
}
func (r *_httpOut_) _growFields(size int) (from int, edge int, ok bool) { // used by growHeaders first and growTrailers later as they are not manipulated at the same time
	if size <= 0 || size > _16K { // size allowed: (0, 16K]
		BugExitln("invalid size in _growFields")
	}
	from = int(r.outputEdge)
	ceil := r.outputEdge + uint16(size)
	last := ceil + 256 // we reserve 256 bytes at the end of r.output for finalizeHeaders()
	if ceil < r.outputEdge || last > _16K || last < ceil {
		// Overflow
		return
	}
	if last > uint16(cap(r.output)) { // cap < last <= _16K
		output := GetNK(int64(last)) // 4K/16K
		copy(output, r.output[0:r.outputEdge])
		if cap(r.output) != cap(r.stockOutput) {
			PutNK(r.output)
		}
		r.output = output
	}
	r.outputEdge = ceil
	edge, ok = int(r.outputEdge), true
	return
}

func (r *_httpOut_) _longTimeCheck(err error) error {
	if err == nil && r._isLongTime() {
		err = httpOutLongTime
	}
	if err != nil {
		r.stream.markBroken()
	}
	return err
}
func (r *_httpOut_) _isLongTime() bool { // reports whether the sending of outgoing content costs a long time
	return r.sendTimeout > 0 && time.Since(r.sendTime) >= r.sendTimeout
}

var ( // _httpOut_ errors
	httpOutLongTime      = errors.New("http outgoing costs a long time")
	httpOutWriteBroken   = errors.New("write broken")
	httpOutUnknownStatus = errors.New("unknown status")
	httpOutAlreadySent   = errors.New("already sent")
	httpOutTooLarge      = errors.New("content too large")
	httpOutMixedContent  = errors.New("mixed content mode")
	httpOutTrailerFailed = errors.New("add trailer failed")
)

// httpSocket
type httpSocket interface {
	Read(dst []byte) (int, error)
	Write(src []byte) (int, error)
	Close() error
}

// _httpSocket_ is a mixin.
type _httpSocket_ struct { // for backendSocket_ and serverSocket_. incoming and outgoing
	// Assocs
	stream httpStream // *backend[1-3]Stream, *server[1-3]Stream
	socket httpSocket // *backend[1-3]Socket, *server[1-3]Socket
	// Stream states (stocks)
	// Stream states (controlled)
	// Stream states (non-zeros)
	asServer bool // treat this socket as a server socket?
	// Stream states (zeros)
	_httpSocket0 // all values in this struct must be zero by default!
}
type _httpSocket0 struct { // for fast reset, entirely
}

func (s *_httpSocket_) onUse(asServer bool) { // for non-zeros
	s.asServer = asServer
}
func (s *_httpSocket_) onEnd() { // for zeros
	s._httpSocket0 = _httpSocket0{}
}

func (s *_httpSocket_) todo() {
}

var ( // _httpSocket_ errors
	httpSocketWriteBroken = errors.New("write broken")
)

const ( // basic http constants
	// version codes
	Version1_0 = 0 // must be 0, default value
	Version1_1 = 1
	Version2   = 2
	Version3   = 3

	// scheme codes
	SchemeHTTP  = 0 // must be 0, default value
	SchemeHTTPS = 1

	// best known http method codes
	MethodGET     = 0x00000001
	MethodHEAD    = 0x00000002
	MethodPOST    = 0x00000004
	MethodPUT     = 0x00000008
	MethodDELETE  = 0x00000010
	MethodCONNECT = 0x00000020
	MethodOPTIONS = 0x00000040
	MethodTRACE   = 0x00000080

	// status codes
	// 1XX
	StatusContinue           = 100
	StatusSwitchingProtocols = 101
	StatusProcessing         = 102
	StatusEarlyHints         = 103
	// 2XX
	StatusOK                         = 200
	StatusCreated                    = 201
	StatusAccepted                   = 202
	StatusNonAuthoritativeInfomation = 203
	StatusNoContent                  = 204
	StatusResetContent               = 205
	StatusPartialContent             = 206
	StatusMultiStatus                = 207
	StatusAlreadyReported            = 208
	StatusIMUsed                     = 226
	// 3XX
	StatusMultipleChoices   = 300
	StatusMovedPermanently  = 301
	StatusFound             = 302
	StatusSeeOther          = 303
	StatusNotModified       = 304
	StatusUseProxy          = 305
	StatusTemporaryRedirect = 307
	StatusPermanentRedirect = 308
	// 4XX
	StatusBadRequest                  = 400
	StatusUnauthorized                = 401
	StatusPaymentRequired             = 402
	StatusForbidden                   = 403
	StatusNotFound                    = 404
	StatusMethodNotAllowed            = 405
	StatusNotAcceptable               = 406
	StatusProxyAuthenticationRequired = 407
	StatusRequestTimeout              = 408
	StatusConflict                    = 409
	StatusGone                        = 410
	StatusLengthRequired              = 411
	StatusPreconditionFailed          = 412
	StatusContentTooLarge             = 413
	StatusURITooLong                  = 414
	StatusUnsupportedMediaType        = 415
	StatusRangeNotSatisfiable         = 416
	StatusExpectationFailed           = 417
	StatusMisdirectedRequest          = 421
	StatusUnprocessableEntity         = 422
	StatusLocked                      = 423
	StatusFailedDependency            = 424
	StatusTooEarly                    = 425
	StatusUpgradeRequired             = 426
	StatusPreconditionRequired        = 428
	StatusTooManyRequests             = 429
	StatusRequestHeaderFieldsTooLarge = 431
	StatusUnavailableForLegalReasons  = 451
	// 5XX
	StatusInternalServerError           = 500
	StatusNotImplemented                = 501
	StatusBadGateway                    = 502
	StatusServiceUnavailable            = 503
	StatusGatewayTimeout                = 504
	StatusHTTPVersionNotSupported       = 505
	StatusVariantAlsoNegotiates         = 506
	StatusInsufficientStorage           = 507
	StatusLoopDetected                  = 508
	StatusNotExtended                   = 510
	StatusNetworkAuthenticationRequired = 511
)

var httpVersionStrings = [...]string{
	Version1_0: stringHTTP1_0,
	Version1_1: stringHTTP1_1,
	Version2:   stringHTTP2,
	Version3:   stringHTTP3,
}

var httpVersionByteses = [...][]byte{
	Version1_0: bytesHTTP1_0,
	Version1_1: bytesHTTP1_1,
	Version2:   bytesHTTP2,
	Version3:   bytesHTTP3,
}

var httpSchemeStrings = [...]string{
	SchemeHTTP:  stringHTTP,
	SchemeHTTPS: stringHTTPS,
}

var httpSchemeByteses = [...][]byte{
	SchemeHTTP:  bytesHTTP,
	SchemeHTTPS: bytesHTTPS,
}

var httpStatus = [11]byte{':', 's', 't', 'a', 't', 'u', 's', ' ', 'n', 'n', 'n'} // used by http/2 and http/3

const ( // misc http type constants
	httpSectionControl  = 0 // must be 0, default value
	httpSectionHeaders  = 1
	httpSectionContent  = 2
	httpSectionTrailers = 3

	httpCodingIdentity = 0 // must be 0, default value
	httpCodingCompress = 1
	httpCodingDeflate  = 2 // this is in fact zlib format
	httpCodingGzip     = 3
	httpCodingBrotli   = 4
	httpCodingUnknown  = 5

	httpFormNotForm    = 0 // must be 0, default value
	httpFormURLEncoded = 1 // application/x-www-form-urlencoded
	httpFormMultipart  = 2 // multipart/form-data

	httpContentTextNone  = 0 // must be 0, default value
	httpContentTextInput = 1 // refers to r.input
	httpContentTextPool  = 2 // fetched from pool
	httpContentTextMake  = 3 // direct make
)

const ( // hashes of http fields. value is calculated by adding all ASCII values.
	// Pseudo header fields
	hashAuthority = 1059 // :authority
	hashMethod    = 699  // :method
	hashPath      = 487  // :path
	hashProtocol  = 940  // :protocol
	hashScheme    = 687  // :scheme
	hashStatus    = 734  // :status
	// General fields
	hashAccept           = 624
	hashAcceptEncoding   = 1508
	hashCacheControl     = 1314 // same with hashLastModified. multiple
	hashConnection       = 1072
	hashContentEncoding  = 1647
	hashContentLanguage  = 1644
	hashContentLength    = 1450
	hashContentLocation  = 1665
	hashContentRange     = 1333
	hashContentType      = 1258
	hashDate             = 414
	hashKeepAlive        = 995
	hashTrailer          = 755
	hashTransferEncoding = 1753
	hashUpgrade          = 744
	hashVia              = 320
	// Request fields
	hashAcceptCharset      = 1415
	hashAcceptLanguage     = 1505
	hashAuthorization      = 1425
	hashCookie             = 634
	hashExpect             = 649
	hashForwarded          = 958
	hashHost               = 446
	hashIfMatch            = 777 // same with hashIfRange. multiple
	hashIfModifiedSince    = 1660
	hashIfNoneMatch        = 1254
	hashIfRange            = 777 // same with hashIfMatch. single
	hashIfUnmodifiedSince  = 1887
	hashMaxForwards        = 1243
	hashProxyAuthorization = 2048
	hashProxyConnection    = 1695
	hashRange              = 525
	hashReferer            = 747
	hashTE                 = 217
	hashUserAgent          = 1019
	hashXForwardedBy       = 1387
	hashXForwardedFor      = 1495
	hashXForwardedHost     = 1614
	hashXForwardedProto    = 1732
	// Response fields
	hashAcceptRanges       = 1309
	hashAge                = 301
	hashAllow              = 543
	hashAltSvc             = 698
	hashCacheStatus        = 1221
	hashCDNCacheControl    = 1668
	hashContentDisposition = 2013
	hashETag               = 417
	hashExpires            = 768
	hashLastModified       = 1314 // same with hashCacheControl. single
	hashLocation           = 857
	hashProxyAuthenticate  = 1902
	hashRetryAfter         = 1141
	hashServer             = 663
	hashSetCookie          = 1011
	hashVary               = 450
	hashWWWAuthenticate    = 1681
)

var ( // byteses of http fields.
	// Pseudo header fields
	bytesAuthority = []byte(":authority")
	bytesMethod    = []byte(":method")
	bytesPath      = []byte(":path")
	bytesProtocol  = []byte(":protocol")
	bytesScheme    = []byte(":scheme")
	bytesStatus    = []byte(":status")
	// General fields
	bytesAccept           = []byte("accept")
	bytesAcceptEncoding   = []byte("accept-encoding")
	bytesCacheControl     = []byte("cache-control")
	bytesConnection       = []byte("connection")
	bytesContentEncoding  = []byte("content-encoding")
	bytesContentLanguage  = []byte("content-language")
	bytesContentLength    = []byte("content-length")
	bytesContentLocation  = []byte("content-location")
	bytesContentRange     = []byte("content-range")
	bytesContentType      = []byte("content-type")
	bytesDate             = []byte("date")
	bytesKeepAlive        = []byte("keep-alive")
	bytesTrailer          = []byte("trailer")
	bytesTransferEncoding = []byte("transfer-encoding")
	bytesUpgrade          = []byte("upgrade")
	bytesVia              = []byte("via")
	// Request fields
	bytesAcceptCharset      = []byte("accept-charset")
	bytesAcceptLanguage     = []byte("accept-language")
	bytesAuthorization      = []byte("authorization")
	bytesCookie             = []byte("cookie")
	bytesExpect             = []byte("expect")
	bytesForwarded          = []byte("forwarded")
	bytesHost               = []byte("host")
	bytesIfMatch            = []byte("if-match")
	bytesIfModifiedSince    = []byte("if-modified-since")
	bytesIfNoneMatch        = []byte("if-none-match")
	bytesIfRange            = []byte("if-range")
	bytesIfUnmodifiedSince  = []byte("if-unmodified-since")
	bytesMaxForwards        = []byte("max-forwards")
	bytesProxyAuthorization = []byte("proxy-authorization")
	bytesProxyConnection    = []byte("proxy-connection")
	bytesRange              = []byte("range")
	bytesReferer            = []byte("referer")
	bytesTE                 = []byte("te")
	bytesUserAgent          = []byte("user-agent")
	bytesXForwardedBy       = []byte("x-forwarded-by")
	bytesXForwardedFor      = []byte("x-forwarded-for")
	bytesXForwardedHost     = []byte("x-forwarded-host")
	bytesXForwardedProto    = []byte("x-forwarded-proto")
	// Response fields
	bytesAcceptRanges       = []byte("accept-ranges")
	bytesAge                = []byte("age")
	bytesAllow              = []byte("allow")
	bytesAltSvc             = []byte("alt-svc")
	bytesCacheStatus        = []byte("cache-status")
	bytesCDNCacheControl    = []byte("cdn-cache-control")
	bytesContentDisposition = []byte("content-disposition")
	bytesETag               = []byte("etag")
	bytesExpires            = []byte("expires")
	bytesLastModified       = []byte("last-modified")
	bytesLocation           = []byte("location")
	bytesProxyAuthenticate  = []byte("proxy-authenticate")
	bytesRetryAfter         = []byte("retry-after")
	bytesServer             = []byte("server")
	bytesSetCookie          = []byte("set-cookie")
	bytesVary               = []byte("vary")
	bytesWWWAuthenticate    = []byte("www-authenticate")
)

const ( // hashes of misc http strings & byteses.
	hashBoundary = 868
	hashFilename = 833
	hashName     = 417
)

const ( // misc http strings.
	stringHTTP         = "http"
	stringHTTPS        = "https"
	stringHTTP1_0      = "HTTP/1.0"
	stringHTTP1_1      = "HTTP/1.1"
	stringHTTP2        = "HTTP/2"
	stringHTTP3        = "HTTP/3"
	stringColonport80  = ":80"
	stringColonport443 = ":443"
	stringSlash        = "/"
	stringAsterisk     = "*"
)

var ( // misc http byteses.
	bytesHTTP           = []byte(stringHTTP)
	bytesHTTPS          = []byte(stringHTTPS)
	bytesHTTP1_0        = []byte(stringHTTP1_0)
	bytesHTTP1_1        = []byte(stringHTTP1_1)
	bytesHTTP2          = []byte(stringHTTP2)
	bytesHTTP3          = []byte(stringHTTP3)
	bytesColonport80    = []byte(stringColonport80)
	bytesColonport443   = []byte(stringColonport443)
	bytesSlash          = []byte(stringSlash)
	bytesAsterisk       = []byte(stringAsterisk)
	bytesGET            = []byte("GET")
	bytes100Continue    = []byte("100-continue")
	bytesBoundary       = []byte("boundary")
	bytesBytes          = []byte("bytes")
	bytesBytesEqual     = []byte("bytes=")
	bytesBytesStarSlash = []byte("bytes */")
	bytesChunked        = []byte("chunked")
	bytesClose          = []byte("close")
	bytesColonSpace     = []byte(": ")
	bytesCompress       = []byte("compress")
	bytesCRLF           = []byte("\r\n")
	bytesDeflate        = []byte("deflate")
	bytesFilename       = []byte("filename")
	bytesFormData       = []byte("form-data")
	bytesGzip           = []byte("gzip")
	bytesBrotli         = []byte("br")
	bytesIdentity       = []byte("identity")
	bytesTypeHTML       = []byte("text/html")
	bytesTypeJSON       = []byte("application/json")
	bytesURLEncodedForm = []byte("application/x-www-form-urlencoded")
	bytesMultipartForm  = []byte("multipart/form-data")
	bytesName           = []byte("name")
	bytesNone           = []byte("none")
	bytesTrailers       = []byte("trailers")
	bytesWebSocket      = []byte("websocket")
	bytesGorox          = []byte("gorox")
	// HTTP/2 and HTTP/3 byteses, TODO
	bytesSchemeHTTP           = []byte(":scheme http")
	bytesSchemeHTTPS          = []byte(":scheme https")
	bytesFixedRequestHeaders  = []byte("client gorox")
	bytesFixedResponseHeaders = []byte("server gorox")
)

var httpTchar = [256]int8{ // tchar = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, //   !   # $ % & '     * +   - .
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 0 1 2 3 4 5 6 7 8 9
	0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, //   A B C D E F G H I J K L M N O
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 1, 3, // P Q R S T U V W X Y Z       ^ _
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // ` a b c d e f g h i j k l m n o
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, // p q r s t u v w x y z   |   ~
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}
var httpPchar = [256]int8{ // pchar = ALPHA / DIGIT / "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / "-" / "." / ":" / ";" / "=" / "@" / "_" / "~" / pct-encoded. '/' is pchar to improve performance.
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //   !     $   & ' ( ) * + , - . /
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 2, // 0 1 2 3 4 5 6 7 8 9 : ;   =   ? // '?' is set to 2 to improve performance
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // @ A B C D E F G H I J K L M N O
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, // P Q R S T U V W X Y Z         _
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //   a b c d e f g h i j k l m n o
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, // p q r s t u v w x y z       ~
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}
var httpKchar = [256]int8{ // cookie-octet = 0x21 / 0x23-0x2B / 0x2D-0x3A / 0x3C-0x5B / 0x5D-0x7E
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, //   !   # $ % & ' ( ) * +   - . /
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, // 0 1 2 3 4 5 6 7 8 9 :   < = > ?
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // @ A B C D E F G H I J K L M N O
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, // P Q R S T U V W X Y Z [   ] ^ _
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // ` a b c d e f g h i j k l m n o
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, // p q r s t u v w x y z { | } ~
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}
var httpHchar = [256]int8{ // for hostname
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, //                           - .
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 0 1 2 3 4 5 6 7 8 9
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //   a b c d e f g h i j k l m n o
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, // p q r s t u v w x y z
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

var httpHuffmanCodes = [256]uint32{ // 1K, for huffman encoding
	0x00001ff8, 0x007fffd8, 0x0fffffe2, 0x0fffffe3, 0x0fffffe4, 0x0fffffe5, 0x0fffffe6, 0x0fffffe7,
	0x0fffffe8, 0x00ffffea, 0x3ffffffc, 0x0fffffe9, 0x0fffffea, 0x3ffffffd, 0x0fffffeb, 0x0fffffec,
	0x0fffffed, 0x0fffffee, 0x0fffffef, 0x0ffffff0, 0x0ffffff1, 0x0ffffff2, 0x3ffffffe, 0x0ffffff3,
	0x0ffffff4, 0x0ffffff5, 0x0ffffff6, 0x0ffffff7, 0x0ffffff8, 0x0ffffff9, 0x0ffffffa, 0x0ffffffb,
	0x00000014, 0x000003f8, 0x000003f9, 0x00000ffa, 0x00001ff9, 0x00000015, 0x000000f8, 0x000007fa,
	0x000003fa, 0x000003fb, 0x000000f9, 0x000007fb, 0x000000fa, 0x00000016, 0x00000017, 0x00000018,
	0x00000000, 0x00000001, 0x00000002, 0x00000019, 0x0000001a, 0x0000001b, 0x0000001c, 0x0000001d,
	0x0000001e, 0x0000001f, 0x0000005c, 0x000000fb, 0x00007ffc, 0x00000020, 0x00000ffb, 0x000003fc,
	0x00001ffa, 0x00000021, 0x0000005d, 0x0000005e, 0x0000005f, 0x00000060, 0x00000061, 0x00000062,
	0x00000063, 0x00000064, 0x00000065, 0x00000066, 0x00000067, 0x00000068, 0x00000069, 0x0000006a,
	0x0000006b, 0x0000006c, 0x0000006d, 0x0000006e, 0x0000006f, 0x00000070, 0x00000071, 0x00000072,
	0x000000fc, 0x00000073, 0x000000fd, 0x00001ffb, 0x0007fff0, 0x00001ffc, 0x00003ffc, 0x00000022,
	0x00007ffd, 0x00000003, 0x00000023, 0x00000004, 0x00000024, 0x00000005, 0x00000025, 0x00000026,
	0x00000027, 0x00000006, 0x00000074, 0x00000075, 0x00000028, 0x00000029, 0x0000002a, 0x00000007,
	0x0000002b, 0x00000076, 0x0000002c, 0x00000008, 0x00000009, 0x0000002d, 0x00000077, 0x00000078,
	0x00000079, 0x0000007a, 0x0000007b, 0x00007ffe, 0x000007fc, 0x00003ffd, 0x00001ffd, 0x0ffffffc,
	0x000fffe6, 0x003fffd2, 0x000fffe7, 0x000fffe8, 0x003fffd3, 0x003fffd4, 0x003fffd5, 0x007fffd9,
	0x003fffd6, 0x007fffda, 0x007fffdb, 0x007fffdc, 0x007fffdd, 0x007fffde, 0x00ffffeb, 0x007fffdf,
	0x00ffffec, 0x00ffffed, 0x003fffd7, 0x007fffe0, 0x00ffffee, 0x007fffe1, 0x007fffe2, 0x007fffe3,
	0x007fffe4, 0x001fffdc, 0x003fffd8, 0x007fffe5, 0x003fffd9, 0x007fffe6, 0x007fffe7, 0x00ffffef,
	0x003fffda, 0x001fffdd, 0x000fffe9, 0x003fffdb, 0x003fffdc, 0x007fffe8, 0x007fffe9, 0x001fffde,
	0x007fffea, 0x003fffdd, 0x003fffde, 0x00fffff0, 0x001fffdf, 0x003fffdf, 0x007fffeb, 0x007fffec,
	0x001fffe0, 0x001fffe1, 0x003fffe0, 0x001fffe2, 0x007fffed, 0x003fffe1, 0x007fffee, 0x007fffef,
	0x000fffea, 0x003fffe2, 0x003fffe3, 0x003fffe4, 0x007ffff0, 0x003fffe5, 0x003fffe6, 0x007ffff1,
	0x03ffffe0, 0x03ffffe1, 0x000fffeb, 0x0007fff1, 0x003fffe7, 0x007ffff2, 0x003fffe8, 0x01ffffec,
	0x03ffffe2, 0x03ffffe3, 0x03ffffe4, 0x07ffffde, 0x07ffffdf, 0x03ffffe5, 0x00fffff1, 0x01ffffed,
	0x0007fff2, 0x001fffe3, 0x03ffffe6, 0x07ffffe0, 0x07ffffe1, 0x03ffffe7, 0x07ffffe2, 0x00fffff2,
	0x001fffe4, 0x001fffe5, 0x03ffffe8, 0x03ffffe9, 0x0ffffffd, 0x07ffffe3, 0x07ffffe4, 0x07ffffe5,
	0x000fffec, 0x00fffff3, 0x000fffed, 0x001fffe6, 0x003fffe9, 0x001fffe7, 0x001fffe8, 0x007ffff3,
	0x003fffea, 0x003fffeb, 0x01ffffee, 0x01ffffef, 0x00fffff4, 0x00fffff5, 0x03ffffea, 0x007ffff4,
	0x03ffffeb, 0x07ffffe6, 0x03ffffec, 0x03ffffed, 0x07ffffe7, 0x07ffffe8, 0x07ffffe9, 0x07ffffea,
	0x07ffffeb, 0x0ffffffe, 0x07ffffec, 0x07ffffed, 0x07ffffee, 0x07ffffef, 0x07fffff0, 0x03ffffee,
}
var httpHuffmanSizes = [256]uint8{ // 256B, for huffman encoding
	0x0d, 0x17, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x18, 0x1e, 0x1c, 0x1c, 0x1e, 0x1c, 0x1c,
	0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1e, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c,
	0x06, 0x0a, 0x0a, 0x0c, 0x0d, 0x06, 0x08, 0x0b, 0x0a, 0x0a, 0x08, 0x0b, 0x08, 0x06, 0x06, 0x06,
	0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x08, 0x0f, 0x06, 0x0c, 0x0a,
	0x0d, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x07, 0x08, 0x0d, 0x13, 0x0d, 0x0e, 0x06,
	0x0f, 0x05, 0x06, 0x05, 0x06, 0x05, 0x06, 0x06, 0x06, 0x05, 0x07, 0x07, 0x06, 0x06, 0x06, 0x05,
	0x06, 0x07, 0x06, 0x05, 0x05, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0b, 0x0e, 0x0d, 0x1c,
	0x14, 0x16, 0x14, 0x14, 0x16, 0x16, 0x16, 0x17, 0x16, 0x17, 0x17, 0x17, 0x17, 0x17, 0x18, 0x17,
	0x18, 0x18, 0x16, 0x17, 0x18, 0x17, 0x17, 0x17, 0x17, 0x15, 0x16, 0x17, 0x16, 0x17, 0x17, 0x18,
	0x16, 0x15, 0x14, 0x16, 0x16, 0x17, 0x17, 0x15, 0x17, 0x16, 0x16, 0x18, 0x15, 0x16, 0x17, 0x17,
	0x15, 0x15, 0x16, 0x15, 0x17, 0x16, 0x17, 0x17, 0x14, 0x16, 0x16, 0x16, 0x17, 0x16, 0x16, 0x17,
	0x1a, 0x1a, 0x14, 0x13, 0x16, 0x17, 0x16, 0x19, 0x1a, 0x1a, 0x1a, 0x1b, 0x1b, 0x1a, 0x18, 0x19,
	0x13, 0x15, 0x1a, 0x1b, 0x1b, 0x1a, 0x1b, 0x18, 0x15, 0x15, 0x1a, 0x1a, 0x1c, 0x1b, 0x1b, 0x1b,
	0x14, 0x18, 0x14, 0x15, 0x16, 0x15, 0x15, 0x17, 0x16, 0x16, 0x19, 0x19, 0x18, 0x18, 0x1a, 0x17,
	0x1a, 0x1b, 0x1a, 0x1a, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1c, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1a,
}

func httpHuffmanLength(src []byte) int {
	n := 0
	for _, b := range src {
		n += int(httpHuffmanSizes[b])
	}
	return (n + 7) / 8
}
func httpHuffmanEncode(dst []byte, src []byte) int {
	// TODO
	return 0
}

var httpHuffmanTable = [256][16]struct {
	next byte
	sym  byte
	emit byte
	end  byte
}{ // 16K, for huffman decoding
	0x00: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x01: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x02: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x03: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x04: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x05: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x06: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x07: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x08: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x09: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x0a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x0b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x0c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x0d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x0e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x0f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x10: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x11: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x12: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x13: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x14: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x15: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x16: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x17: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x18: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x19: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x1a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x1b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x1c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x1d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x1e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x1f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x20: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x21: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x22: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x23: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x24: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x25: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x26: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x27: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x28: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x29: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x2a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x2b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x2c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x2d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x2e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x2f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x30: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x31: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x32: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x33: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x34: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x35: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x36: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x37: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x38: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x39: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x3a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x3b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x3c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x3d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x3e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x3f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x40: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x41: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x42: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x43: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x44: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x45: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x46: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x47: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x48: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x49: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x4a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x4b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x4c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x4d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x4e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x4f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x50: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x51: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x52: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x53: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x54: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x55: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x56: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x57: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x58: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x59: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x5a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x5b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x5c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x5d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x5e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x5f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x60: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x61: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x62: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x63: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x64: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x65: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x66: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x67: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x68: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x69: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x6a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x6b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x6c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x6d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x6e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x6f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x70: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x71: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x72: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x73: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x74: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x75: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x76: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x77: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x78: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x79: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x7a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x7b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x7c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x7d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x7e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x7f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x80: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x81: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x82: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x83: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x84: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x85: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x86: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x87: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x88: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x89: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x8a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x8b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x8c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x8d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x8e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x8f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x90: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x91: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x92: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x93: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x94: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x95: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x96: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x97: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x98: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x99: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x9a: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x9b: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x9c: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x9d: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x9e: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0x9f: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa0: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa1: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa2: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa3: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa4: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa5: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa6: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa7: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa8: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xa9: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xaa: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xab: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xac: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xad: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xae: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xaf: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb0: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb1: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb2: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb3: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb4: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb5: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb6: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb7: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb8: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xb9: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xba: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xbb: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xbc: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xbd: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xbe: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xbf: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc0: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc1: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc2: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc3: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc4: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc5: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc6: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc7: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc8: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xc9: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xca: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xcb: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xcc: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xcd: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xce: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xcf: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd0: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd1: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd2: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd3: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd4: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd5: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd6: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd7: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd8: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xd9: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xda: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xdb: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xdc: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xdd: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xde: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xdf: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe0: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe1: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe2: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe3: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe4: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe5: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe6: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe7: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe8: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xe9: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xea: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xeb: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xec: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xed: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xee: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xef: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf0: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf1: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf2: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf3: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf4: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf5: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf6: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf7: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf8: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xf9: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xfa: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xfb: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xfc: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xfd: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xfe: {
		{0x04, 0x00, 0, 0}, {0x05, 0x00, 0, 0}, {0x07, 0x00, 0, 0}, {0x08, 0x00, 0, 0}, {0x0b, 0x00, 0, 0}, {0x0c, 0x00, 0, 0}, {0x10, 0x00, 0, 0}, {0x13, 0x00, 0, 0},
		{0x19, 0x00, 0, 0}, {0x1c, 0x00, 0, 0}, {0x20, 0x00, 0, 0}, {0x23, 0x00, 0, 0}, {0x2a, 0x00, 0, 0}, {0x31, 0x00, 0, 0}, {0x39, 0x00, 0, 0}, {0x40, 0x00, 0, 1},
	},
	0xff: {
		{0x03, 0x16, 1, 0}, {0x06, 0x16, 1, 0}, {0x0a, 0x16, 1, 0}, {0x0f, 0x16, 1, 0}, {0x18, 0x16, 1, 0}, {0x1f, 0x16, 1, 0}, {0x29, 0x16, 1, 0}, {0x38, 0x16, 1, 1},
		{0xff, 0x00, 0, 0}, {0xff, 0x00, 0, 0}, {0xff, 0x00, 0, 0}, {0xff, 0x00, 0, 0}, {0xff, 0x00, 0, 0}, {0xff, 0x00, 0, 0}, {0xff, 0x00, 0, 0}, {0xff, 0x00, 0, 0},
	},
}

func httpHuffmanDecode(dst []byte, src []byte) (int, bool) {
	// TODO
	return 0, false
}

// Range defines a range.
type Range struct { // 16 bytes
	From, Last int64 // [From:Last], inclusive
}

// defaultFdesc
var defaultFdesc = &fdesc{
	allowQuote: true,
	allowEmpty: false,
	allowParam: true,
	hasComment: false,
}

// fdesc describes an http field.
type fdesc struct {
	nameHash   uint16 // name hash
	allowQuote bool   // allow data quote or not
	allowEmpty bool   // allow empty data or not
	allowParam bool   // allow parameters or not
	hasComment bool   // has comment or not
	name       []byte // field name
}

// pair is used to hold queries, headerLines, cookies, forms, trailerLines, and params.
type pair struct { // 24 bytes
	nameHash uint16 // name hash, to support fast search. 0 means empty pair
	kind     int8   // see pair kinds
	nameSize uint8  // must <= 255
	nameFrom int32  // name edge at nameFrom+nameSize
	value    span   // the value
	place    int8   // see pair places
	flags    byte   // fields only. see field flags
	params   zone   // fields only. refers to a zone of pairs
	dataEdge int32  // fields only. data ends at
}

var poolPairs sync.Pool

const maxPairs = 250 // 24B*250=6000B

func getPairs() []pair {
	if x := poolPairs.Get(); x == nil {
		return make([]pair, 0, maxPairs)
	} else {
		return x.([]pair)
	}
}
func putPairs(pairs []pair) {
	if cap(pairs) != maxPairs {
		BugExitln("bad pairs")
	}
	pairs = pairs[0:0:maxPairs] // reset
	poolPairs.Put(pairs)
}

// If "foobar-type" field is defined as: `allowQuote=true allowEmpty=false allowParam=true`, then a non-comma "foobar-type" field may looks like this:
//
//                                 [         params         )
//                     [               value                )
//        [   name   )  [  data   )  [    param1    )[param2)
//       +--------------------------------------------------+
//       |foobar-type: "text/plain"; charset="utf-8";lang=en|
//       +--------------------------------------------------+
//        ^          ^ ^^         ^                         ^
//        |          | ||         |                         |
// nameFrom          | ||         dataEdge                  |
//   nameFrom+nameSize ||                                   |
//            value.from|                          value.edge
//                      |
//                      dataFrom=value.from+(flags&flagQuoted)
//
// For dataFrom, if data is quoted, then flagQuoted is set, so flags&flagQuoted is 1, which skips '"' exactly.
//
// A has-comma "foobar-types" field may looks like this (needs further parsing into sub fields):
//
// +-----------------------------------------------------------------------------------------------------------------+
// |foobar-types: "text/plain"; ;charset="utf-8";langs="en,zh" ,,; ;charset="" ,,application/octet-stream ;,image/png|
// +-----------------------------------------------------------------------------------------------------------------+

const ( // pair kinds, max 8 kinds allowed
	pairUnknown = iota
	pairQuery   // plain kv
	pairHeader  // field
	pairCookie  // plain kv
	pairForm    // plain kv
	pairTrailer // field
	pairParam   // parameter of fields, plain kv
)

const ( // pair places
	placeInput   = iota
	placeArray   // parsed
	placeStatic2 // http/2 static table
	placeStatic3 // http/3 static table
)

const ( // field flags
	flagParsed     = 0b10000000 // data and params are parsed or not
	flagSingleton  = 0b01000000 // singleton or not. mainly used by proxies
	flagSubField   = 0b00100000 // sub field or not. mainly used by webapps
	flagLiteral    = 0b00010000 // keep literal or not. used in HTTP/2 and HTTP/3
	flagPseudo     = 0b00001000 // pseudo header or not. used in HTTP/2 and HTTP/3
	flagUnderscore = 0b00000100 // name contains '_' or not. some proxies need this information
	flagCommaValue = 0b00000010 // value has comma or not
	flagQuoted     = 0b00000001 // data is quoted or not. for non comma-value field only. MUST be 0b00000001
)

func (p *pair) zero() { *p = pair{} }

func (p *pair) nameAt(t []byte) []byte { return t[p.nameFrom : p.nameFrom+int32(p.nameSize)] }
func (p *pair) nameEqualString(t []byte, x string) bool {
	return int(p.nameSize) == len(x) && string(t[p.nameFrom:p.nameFrom+int32(p.nameSize)]) == x
}
func (p *pair) nameEqualBytes(t []byte, x []byte) bool {
	return int(p.nameSize) == len(x) && bytes.Equal(t[p.nameFrom:p.nameFrom+int32(p.nameSize)], x)
}
func (p *pair) valueAt(t []byte) []byte { return t[p.value.from:p.value.edge] }

func (p *pair) setParsed()     { p.flags |= flagParsed }
func (p *pair) setSingleton()  { p.flags |= flagSingleton }
func (p *pair) setSubField()   { p.flags |= flagSubField }
func (p *pair) setLiteral()    { p.flags |= flagLiteral }
func (p *pair) setPseudo()     { p.flags |= flagPseudo }
func (p *pair) setUnderscore() { p.flags |= flagUnderscore }
func (p *pair) setCommaValue() { p.flags |= flagCommaValue }
func (p *pair) setQuoted()     { p.flags |= flagQuoted }

func (p *pair) isParsed() bool     { return p.flags&flagParsed > 0 }
func (p *pair) isSingleton() bool  { return p.flags&flagSingleton > 0 }
func (p *pair) isSubField() bool   { return p.flags&flagSubField > 0 }
func (p *pair) isLiteral() bool    { return p.flags&flagLiteral > 0 }
func (p *pair) isPseudo() bool     { return p.flags&flagPseudo > 0 }
func (p *pair) isUnderscore() bool { return p.flags&flagUnderscore > 0 }
func (p *pair) isCommaValue() bool { return p.flags&flagCommaValue > 0 }
func (p *pair) isQuoted() bool     { return p.flags&flagQuoted > 0 }

func (p *pair) dataAt(t []byte) []byte { return t[p.value.from+int32(p.flags&flagQuoted) : p.dataEdge] }
func (p *pair) dataEmpty() bool        { return p.value.from+int32(p.flags&flagQuoted) == p.dataEdge }

func (p *pair) show(place []byte) { // TODO: optimize, or simply remove
	var kind string
	switch p.kind {
	case pairQuery:
		kind = "query"
	case pairHeader:
		kind = "header"
	case pairCookie:
		kind = "cookie"
	case pairForm:
		kind = "form"
	case pairTrailer:
		kind = "trailer"
	case pairParam:
		kind = "param"
	default:
		kind = "unknown"
	}
	var plase string
	switch p.place {
	case placeInput:
		plase = "input"
	case placeArray:
		plase = "array"
	case placeStatic2:
		plase = "static2"
	case placeStatic3:
		plase = "static3"
	default:
		plase = "unknown"
	}
	var flags []string
	if p.isParsed() {
		flags = append(flags, "parsed")
	}
	if p.isSingleton() {
		flags = append(flags, "singleton")
	}
	if p.isSubField() {
		flags = append(flags, "subField")
	}
	if p.isCommaValue() {
		flags = append(flags, "commaValue")
	}
	if p.isQuoted() {
		flags = append(flags, "quoted")
	}
	if len(flags) == 0 {
		flags = append(flags, "nothing")
	}
	Printf("{nameHash=%4d kind=%7s place=[%7s] flags=[%s] dataEdge=%d params=%v value=%v %s=%s}\n", p.nameHash, kind, plase, strings.Join(flags, ","), p.dataEdge, p.params, p.value, p.nameAt(place), p.valueAt(place))
}

// para is a name-value parameter in fields.
type para struct { // 16 bytes
	name, value span
}

// zone
type zone struct { // 2 bytes
	from, edge uint8 // edge is ensured to be <= 255
}

func (z *zone) zero() { *z = zone{} }

func (z *zone) size() int      { return int(z.edge - z.from) }
func (z *zone) isEmpty() bool  { return z.from == z.edge }
func (z *zone) notEmpty() bool { return z.from != z.edge }

// span
type span struct { // 8 bytes
	from, edge int32 // p[from:edge] is the bytes. edge is ensured to be <= 2147483647
}

func (s *span) zero() { *s = span{} }

func (s *span) size() int      { return int(s.edge - s.from) }
func (s *span) isEmpty() bool  { return s.from == s.edge }
func (s *span) notEmpty() bool { return s.from != s.edge }

func (s *span) set(from int32, edge int32) {
	s.from, s.edge = from, edge
}
func (s *span) sub(delta int32) {
	if s.from >= delta {
		s.from -= delta
		s.edge -= delta
	}
}

// Piece is a member of content chain.
type Piece struct { // 64 bytes
	next *Piece   // next piece
	pool bool     // true if this piece is got from poolPiece. don't change this after set!
	shut bool     // close file on free()?
	kind int8     // 0:text 1:*os.File
	_    [5]byte  // padding
	text []byte   // text
	file *os.File // file
	size int64    // size of text or file
	time int64    // file mod time
}

var poolPiece sync.Pool

func GetPiece() *Piece {
	if x := poolPiece.Get(); x == nil {
		piece := new(Piece)
		piece.pool = true // other pieces are not pooled.
		return piece
	} else {
		return x.(*Piece)
	}
}
func putPiece(piece *Piece) { poolPiece.Put(piece) }

func (p *Piece) zero() {
	p.closeFile()
	p.next = nil
	p.shut = false
	p.kind = 0
	p.text = nil
	p.file = nil
	p.size = 0
	p.time = 0
}
func (p *Piece) closeFile() {
	if p.IsText() {
		return
	}
	if p.shut {
		p.file.Close()
	}
	if DebugLevel() >= 2 {
		if p.shut {
			Println("file closed in Piece.closeFile()")
		} else {
			Println("file *NOT* closed in Piece.closeFile()")
		}
	}
}

func (p *Piece) copyTo(buffer []byte) error { // buffer is large enough, and p is a file.
	if p.IsText() {
		BugExitln("copyTo when piece is text")
	}
	sizeRead := int64(0)
	for {
		if sizeRead == p.size {
			return nil
		}
		readSize := int64(cap(buffer))
		if sizeLeft := p.size - sizeRead; sizeLeft < readSize {
			readSize = sizeLeft
		}
		n, err := p.file.ReadAt(buffer[:readSize], sizeRead)
		sizeRead += int64(n)
		if err != nil && sizeRead != p.size {
			return err
		}
	}
}

func (p *Piece) Next() *Piece { return p.next }

func (p *Piece) IsText() bool { return p.kind == 0 }
func (p *Piece) IsFile() bool { return p.kind == 1 }

func (p *Piece) SetText(text []byte) {
	p.closeFile()
	p.shut = false
	p.kind = 0
	p.text = text
	p.file = nil
	p.size = int64(len(text))
	p.time = 0
}
func (p *Piece) SetFile(file *os.File, info os.FileInfo, shut bool) {
	p.closeFile()
	p.shut = shut
	p.kind = 1
	p.text = nil
	p.file = file
	p.size = info.Size()
	p.time = info.ModTime().Unix()
}

func (p *Piece) Text() []byte {
	if !p.IsText() {
		BugExitln("piece is not text")
	}
	if p.size == 0 {
		return nil
	}
	return p.text
}
func (p *Piece) File() *os.File {
	if !p.IsFile() {
		BugExitln("piece is not file")
	}
	return p.file
}

// Chain is a linked-list of pieces.
type Chain struct { // 24 bytes
	head *Piece
	tail *Piece
	qnty int
}

func (c *Chain) free() {
	if DebugLevel() >= 2 {
		Printf("chain.free() called, qnty=%d\n", c.qnty)
	}
	if c.qnty == 0 {
		return
	}
	piece := c.head
	c.head, c.tail = nil, nil
	qnty := 0
	for piece != nil {
		next := piece.next
		piece.zero()
		if piece.pool { // only put those got from poolPiece because they are not fixed
			putPiece(piece)
		}
		qnty++
		piece = next
	}
	if qnty != c.qnty {
		BugExitf("bad chain: qnty=%d c.qnty=%d\n", qnty, c.qnty)
	}
	c.qnty = 0
}

func (c *Chain) Qnty() int { return c.qnty }
func (c *Chain) Size() (int64, bool) {
	size := int64(0)
	for piece := c.head; piece != nil; piece = piece.next {
		size += piece.size
		if size < 0 {
			return 0, false
		}
	}
	return size, true
}

func (c *Chain) PushHead(piece *Piece) {
	if piece == nil {
		return
	}
	if c.qnty == 0 {
		c.head, c.tail = piece, piece
	} else {
		piece.next = c.head
		c.head = piece
	}
	c.qnty++
}
func (c *Chain) PushTail(piece *Piece) {
	if piece == nil {
		return
	}
	if c.qnty == 0 {
		c.head, c.tail = piece, piece
	} else {
		c.tail.next = piece
		c.tail = piece
	}
	c.qnty++
}

// Upfile is a file uploaded by http client and used by http server.
type Upfile struct { // 48 bytes
	nameHash uint16 // hash of name, to support fast comparison
	flags    uint8  // see upfile flags
	errCode  int8   // error code
	nameSize uint8  // name size
	baseSize uint8  // base size
	typeSize uint8  // type size
	pathSize uint8  // path size
	nameFrom int32  // like: "avatar"
	baseFrom int32  // like: "michael.jpg"
	typeFrom int32  // like: "image/jpeg"
	pathFrom int32  // like: "/path/to/391384576"
	size     int64  // file size
	meta     string // cannot use []byte as it can cause memory leak if caller save file to another place
}

func (u *Upfile) nameEqualString(p []byte, x string) bool {
	if int(u.nameSize) != len(x) {
		return false
	}
	if u.metaSet() {
		return u.meta[u.nameFrom:u.nameFrom+int32(u.nameSize)] == x
	}
	return string(p[u.nameFrom:u.nameFrom+int32(u.nameSize)]) == x
}

const ( // upfile flags
	upfileFlagMetaSet = 0b10000000
	upfileFlagIsMoved = 0b01000000
)

func (u *Upfile) setMeta(p []byte) {
	if u.flags&upfileFlagMetaSet > 0 {
		return
	}
	u.flags |= upfileFlagMetaSet
	from := u.nameFrom
	if u.baseFrom < from {
		from = u.baseFrom
	}
	if u.pathFrom < from {
		from = u.pathFrom
	}
	if u.typeFrom < from {
		from = u.typeFrom
	}
	max, edge := u.typeFrom, u.typeFrom+int32(u.typeSize)
	if u.pathFrom > max {
		max = u.pathFrom
		edge = u.pathFrom + int32(u.pathSize)
	}
	if u.baseFrom > max {
		max = u.baseFrom
		edge = u.baseFrom + int32(u.baseSize)
	}
	if u.nameFrom > max {
		max = u.nameFrom
		edge = u.nameFrom + int32(u.nameSize)
	}
	u.meta = string(p[from:edge]) // dup to avoid memory leak
	u.nameFrom -= from
	u.baseFrom -= from
	u.typeFrom -= from
	u.pathFrom -= from
}
func (u *Upfile) metaSet() bool { return u.flags&upfileFlagMetaSet > 0 }
func (u *Upfile) setMoved()     { u.flags |= upfileFlagIsMoved }
func (u *Upfile) isMoved() bool { return u.flags&upfileFlagIsMoved > 0 }

const ( // upfile error codes
	upfileOK        = 0
	upfileError     = 1
	upfileCantWrite = 2
	upfileTooLarge  = 3
	upfilePartial   = 4
	upfileNoFile    = 5
)

var upfileErrors = [...]error{
	nil, // no error
	errors.New("general error"),
	errors.New("cannot write"),
	errors.New("too large"),
	errors.New("partial"),
	errors.New("no file"),
}

func (u *Upfile) IsOK() bool   { return u.errCode == 0 }
func (u *Upfile) Error() error { return upfileErrors[u.errCode] }

func (u *Upfile) Name() string { return u.meta[u.nameFrom : u.nameFrom+int32(u.nameSize)] }
func (u *Upfile) Base() string { return u.meta[u.baseFrom : u.baseFrom+int32(u.baseSize)] }
func (u *Upfile) Type() string { return u.meta[u.typeFrom : u.typeFrom+int32(u.typeSize)] }
func (u *Upfile) Path() string { return u.meta[u.pathFrom : u.pathFrom+int32(u.pathSize)] }
func (u *Upfile) Size() int64  { return u.size }

func (u *Upfile) MoveTo(path string) error {
	// TODO. Remember to mark as moved
	return nil
}

// Cookie is a "set-cookie" header that is sent to http client by http server.
type Cookie struct {
	name     string
	value    string
	expires  time.Time
	domain   string
	path     string
	sameSite string
	maxAge   int32
	secure   bool
	httpOnly bool
	invalid  bool
	quote    bool // if true, quote value with ""
	aSize    int8
	ageBuf   [10]byte
}

func (c *Cookie) Set(name string, value string) bool {
	// cookie-name = 1*cookie-octet
	// cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
	if name == "" {
		c.invalid = true
		return false
	}
	for i := range len(name) {
		if b := name[i]; httpKchar[b] == 0 {
			c.invalid = true
			return false
		}
	}
	c.name = name
	// cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
	for i := range len(value) {
		b := value[i]
		if httpKchar[b] == 1 {
			continue
		}
		if b == ' ' || b == ',' {
			c.quote = true
			continue
		}
		c.invalid = true
		return false
	}
	c.value = value
	return true
}

func (c *Cookie) SetDomain(domain string) bool {
	// TODO: check domain
	c.domain = domain
	return true
}
func (c *Cookie) SetPath(path string) bool {
	// path-value = *av-octet
	// av-octet = %x20-3A / %x3C-7E
	for i := range len(path) {
		if b := path[i]; b < 0x20 || b > 0x7E || b == 0x3B {
			c.invalid = true
			return false
		}
	}
	c.path = path
	return true
}
func (c *Cookie) SetExpires(expires time.Time) bool {
	expires = expires.UTC()
	if expires.Year() < 1601 {
		c.invalid = true
		return false
	}
	c.expires = expires
	return true
}
func (c *Cookie) SetMaxAge(maxAge int32)  { c.maxAge = maxAge }
func (c *Cookie) SetSecure()              { c.secure = true }
func (c *Cookie) SetHttpOnly()            { c.httpOnly = true }
func (c *Cookie) SetSameSiteStrict()      { c.sameSite = "Strict" }
func (c *Cookie) SetSameSiteLax()         { c.sameSite = "Lax" }
func (c *Cookie) SetSameSiteNone()        { c.sameSite = "None" }
func (c *Cookie) SetSameSite(mode string) { c.sameSite = mode }

func (c *Cookie) size() int {
	// set-cookie: name=value; Expires=Sun, 06 Nov 1994 08:49:37 GMT; Max-Age=123; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict
	n := len(c.name) + 1 + len(c.value) // name=value
	if c.quote {
		n += 2 // ""
	}
	if !c.expires.IsZero() {
		n += len("; Expires=Sun, 06 Nov 1994 08:49:37 GMT")
	}
	if c.maxAge > 0 {
		m := i32ToDec(c.maxAge, c.ageBuf[:])
		c.aSize = int8(m)
		n += len("; Max-Age=") + m
	} else if c.maxAge < 0 {
		c.ageBuf[0] = '0'
		c.aSize = 1
		n += len("; Max-Age=0")
	}
	if c.domain != "" {
		n += len("; Domain=") + len(c.domain)
	}
	if c.path != "" {
		n += len("; Path=") + len(c.path)
	}
	if c.secure {
		n += len("; Secure")
	}
	if c.httpOnly {
		n += len("; HttpOnly")
	}
	if c.sameSite != "" {
		n += len("; SameSite=") + len(c.sameSite)
	}
	return n
}
func (c *Cookie) writeTo(dst []byte) int {
	i := copy(dst, c.name)
	dst[i] = '='
	i++
	if c.quote {
		dst[i] = '"'
		i++
		i += copy(dst[i:], c.value)
		dst[i] = '"'
		i++
	} else {
		i += copy(dst[i:], c.value)
	}
	if !c.expires.IsZero() {
		i += copy(dst[i:], "; Expires=")
		i += clockWriteHTTPDate(dst[i:], c.expires)
	}
	if c.maxAge != 0 {
		i += copy(dst[i:], "; Max-Age=")
		i += copy(dst[i:], c.ageBuf[0:c.aSize])
	}
	if c.domain != "" {
		i += copy(dst[i:], "; Domain=")
		i += copy(dst[i:], c.domain)
	}
	if c.path != "" {
		i += copy(dst[i:], "; Path=")
		i += copy(dst[i:], c.path)
	}
	if c.secure {
		i += copy(dst[i:], "; Secure")
	}
	if c.httpOnly {
		i += copy(dst[i:], "; HttpOnly")
	}
	if c.sameSite != "" {
		i += copy(dst[i:], "; SameSite=")
		i += copy(dst[i:], c.sameSite)
	}
	return i
}
