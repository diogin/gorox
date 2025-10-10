// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// General types and elements for net, rpc, and web.

package hemi

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"regexp"
	"sync"
	"time"
)

// holder
type holder interface {
	Stage() *Stage
	Address() string
	UDSMode() bool
	TLSMode() bool
	ReadTimeout() time.Duration
	WriteTimeout() time.Duration
}

// _holder_ is a mixin.
type _holder_ struct { // for Node_, Server_, and Gate_
	// Assocs
	stage *Stage // current stage
	// States
	address      string        // :port, hostname:port, /path/to/unix.sock
	udsMode      bool          // is address a unix domain socket?
	tlsMode      bool          // use tls to secure the transport?
	tlsConfig    *tls.Config   // set if tls mode is true
	readTimeout  time.Duration // read() timeout
	writeTimeout time.Duration // write() timeout
}

func (h *_holder_) onConfigure(comp Component, defaultRead time.Duration, defaultWrite time.Duration) {
	// .tlsMode
	comp.ConfigureBool("tlsMode", &h.tlsMode, false)
	if h.tlsMode {
		h.tlsConfig = new(tls.Config)
	}

	// .readTimeout
	comp.ConfigureDuration("readTimeout", &h.readTimeout, func(value time.Duration) error {
		if value > 0 {
			return nil
		}
		return errors.New(".readTimeout has an invalid value")
	}, defaultRead)

	// .writeTimeout
	comp.ConfigureDuration("writeTimeout", &h.writeTimeout, func(value time.Duration) error {
		if value > 0 {
			return nil
		}
		return errors.New(".writeTimeout has an invalid value")
	}, defaultWrite)
}
func (h *_holder_) onPrepare(comp Component) {
}

func (h *_holder_) Stage() *Stage { return h.stage }

func (h *_holder_) Address() string             { return h.address }
func (h *_holder_) UDSMode() bool               { return h.udsMode }
func (h *_holder_) TLSMode() bool               { return h.tlsMode }
func (h *_holder_) TLSConfig() *tls.Config      { return h.tlsConfig }
func (h *_holder_) ReadTimeout() time.Duration  { return h.readTimeout }
func (h *_holder_) WriteTimeout() time.Duration { return h.writeTimeout }

// contentSaver
type contentSaver interface { // for _contentSaver_
	RecvTimeout() time.Duration  // timeout to recv the whole message content. zero means no timeout
	SendTimeout() time.Duration  // timeout to send the whole message. zero means no timeout
	MaxContentSize() int64       // max content size allowed
	SaveContentFilesDir() string // the dir to save content temporarily
}

// _contentSaver_ is a mixin.
type _contentSaver_ struct {
	// States
	recvTimeout         time.Duration // timeout to recv the whole message content. zero means no timeout
	sendTimeout         time.Duration // timeout to send the whole message. zero means no timeout
	maxContentSize      int64         // max content size allowed to receive
	saveContentFilesDir string        // temp content files are placed here
}

func (s *_contentSaver_) onConfigure(comp Component, defaultRecv time.Duration, defaultSend time.Duration, defaultDir string) {
	// .recvTimeout
	comp.ConfigureDuration("recvTimeout", &s.recvTimeout, func(value time.Duration) error {
		if value >= 0 {
			return nil
		}
		return errors.New(".recvTimeout has an invalid value")
	}, defaultRecv)

	// .sendTimeout
	comp.ConfigureDuration("sendTimeout", &s.sendTimeout, func(value time.Duration) error {
		if value >= 0 {
			return nil
		}
		return errors.New(".sendTimeout has an invalid value")
	}, defaultSend)

	// .maxContentSize
	comp.ConfigureInt64("maxContentSize", &s.maxContentSize, func(value int64) error {
		if value > 0 {
			return nil
		}
		return errors.New(".maxContentSize has an invalid value")
	}, _1T)

	// .saveContentFilesDir
	comp.ConfigureString("saveContentFilesDir", &s.saveContentFilesDir, func(value string) error {
		if value != "" && len(value) <= 232 {
			return nil
		}
		return errors.New(".saveContentFilesDir has an invalid value")
	}, defaultDir)
}
func (s *_contentSaver_) onPrepare(comp Component, perm os.FileMode) {
	if err := os.MkdirAll(s.saveContentFilesDir, perm); err != nil {
		EnvExitln(err.Error())
	}
	if s.saveContentFilesDir[len(s.saveContentFilesDir)-1] != '/' {
		s.saveContentFilesDir += "/"
	}
}

func (s *_contentSaver_) RecvTimeout() time.Duration  { return s.recvTimeout }
func (s *_contentSaver_) SendTimeout() time.Duration  { return s.sendTimeout }
func (s *_contentSaver_) MaxContentSize() int64       { return s.maxContentSize }
func (s *_contentSaver_) SaveContentFilesDir() string { return s.saveContentFilesDir } // must ends with '/'

// _accessLogger_ is a mixin.
type _accessLogger_ struct { // for router_, Webapp, and Service
	// States
	useLogger string    // "noop", "simple", ...
	logConfig LogConfig // used to configure logger
	logger    Logger    // the logger
}

func (l *_accessLogger_) onConfigure(comp Component) {
	// .useLogger
	comp.ConfigureString("useLogger", &l.useLogger, func(value string) error {
		if loggerRegistered(value) {
			return nil
		}
		return errors.New(".useLogger has an unknown value")
	}, "noop")

	// .logConfig
	if v, ok := comp.Find("logConfig"); ok {
		vLogConfig, ok := v.Dict()
		if !ok {
			UseExitln(".logConfig must be a dict")
		}
		// target
		vTarget, ok := vLogConfig["target"]
		if !ok {
			UseExitln("target is required in .logConfig")
		}
		if target, ok := vTarget.String(); ok {
			l.logConfig.Target = target
		} else {
			UseExitln("target in .logConfig must be a string")
		}
		// bufLen
		vBufLen, ok := vLogConfig["bufLen"]
		if ok {
			if bufLen, ok := vBufLen.Int32(); ok && bufLen >= _1K {
				l.logConfig.BufLen = bufLen
			} else {
				UseExitln("invalid bufLen in .logConfig")
			}
		} else {
			l.logConfig.BufLen = _4K
		}
	}
}
func (l *_accessLogger_) onPrepare(comp Component) {
	logger := createLogger(l.useLogger, &l.logConfig)
	if logger == nil {
		UseExitln("cannot create logger")
	}
	l.logger = logger
}

func (l *_accessLogger_) Logf(f string, v ...any) { l.logger.Logf(f, v...) }

func (l *_accessLogger_) CloseLog() { l.logger.Close() }

// Logger
type Logger interface {
	Logf(f string, v ...any)
	Close()
}

// LogConfig
type LogConfig struct {
	Target string   // "/path/to/file.log", "1.2.3.4:5678", ...
	Rotate string   // "day", "hour", ...
	Fields []string // ("uri", "status"), ...
	BufLen int32    // size of log buffer
}

var (
	loggersLock    sync.RWMutex
	loggerCreators = make(map[string]func(logConfig *LogConfig) Logger) // indexed by loggerSign
)

func RegisterLogger(loggerSign string, create func(logConfig *LogConfig) Logger) {
	loggersLock.Lock()
	defer loggersLock.Unlock()

	if _, ok := loggerCreators[loggerSign]; ok {
		BugExitln("logger conflicts")
	}
	loggerCreators[loggerSign] = create
}
func loggerRegistered(loggerSign string) bool {
	loggersLock.Lock()
	_, ok := loggerCreators[loggerSign]
	loggersLock.Unlock()
	return ok
}
func createLogger(loggerSign string, logConfig *LogConfig) Logger {
	loggersLock.Lock()
	defer loggersLock.Unlock()

	if create := loggerCreators[loggerSign]; create != nil {
		return create(logConfig)
	}
	return nil
}

func init() {
	RegisterLogger("noop", func(logConfig *LogConfig) Logger {
		return noopLogger{}
	})
}

// noopLogger
type noopLogger struct{}

func (noopLogger) Logf(f string, v ...any) {}

func (noopLogger) Close() {}

// Region
type Region struct { // 512B
	blocks [][]byte  // the blocks. [<stocks>/make]
	stocks [4][]byte // for blocks. 96B
	block0 [392]byte // for blocks[0]
}

func (r *Region) Init() {
	r.blocks = r.stocks[0:1:cap(r.stocks)]                    // block0 always at 0
	r.stocks[0] = r.block0[:]                                 // first block is always block0
	binary.BigEndian.PutUint16(r.block0[cap(r.block0)-2:], 0) // reset used size of block0
}
func (r *Region) Make(size int) []byte { // good for a lot of small buffers
	if size <= 0 {
		BugExitln("bad size")
	}
	block := r.blocks[len(r.blocks)-1]
	edge := cap(block)
	ceil := edge - 2
	used := int(binary.BigEndian.Uint16(block[ceil:edge]))
	want := used + size
	if want <= 0 {
		BugExitln("size too large")
	}
	if want <= ceil {
		binary.BigEndian.PutUint16(block[ceil:edge], uint16(want))
		return block[used:want]
	}
	ceil = _4K - 2
	if size > ceil {
		return make([]byte, size)
	}
	block = Get4K()
	binary.BigEndian.PutUint16(block[ceil:_4K], uint16(size))
	r.blocks = append(r.blocks, block)
	return block[0:size]
}
func (r *Region) Free() {
	for i := 1; i < len(r.blocks); i++ {
		PutNK(r.blocks[i])
		r.blocks[i] = nil
	}
	if cap(r.blocks) != cap(r.stocks) {
		r.stocks = [4][]byte{}
		r.blocks = nil
	}
}

// poolElem
type poolElem[C io.Closer] struct {
	next *poolElem[C]
	conn C
}

var poolElems sync.Pool

func getPoolElem[C io.Closer]() *poolElem[C] {
	var elem *poolElem[C]
	if x := poolElems.Get(); x == nil {
		elem = new(poolElem[C])
	} else {
		elem = x.(*poolElem[C])
	}
	return elem
}
func putPoolElem[C io.Closer](elem *poolElem[C]) {
	elem.next = nil
	var null C // nil
	elem.conn = null
	poolElems.Put(elem)
}

// connPool
type connPool[C io.Closer] struct {
	sync.Mutex
	head *poolElem[C]
	tail *poolElem[C]
	qnty int
}

func (p *connPool[C]) pullConn() C {
	p.Lock()
	defer p.Unlock()

	var conn C
	if p.qnty > 0 {
		elem := p.head
		p.head = elem.next
		conn = elem.conn
		putPoolElem(elem)
		p.qnty--
	}
	return conn
}
func (p *connPool[C]) pushConn(conn C) {
	p.Lock()
	defer p.Unlock()

	elem := getPoolElem[C]()
	elem.next = nil
	elem.conn = conn

	if p.qnty == 0 {
		p.head = elem
	} else {
		p.tail.next = elem
	}
	p.tail = elem
	p.qnty++
}

func (p *connPool[C]) closeIdle() int {
	p.Lock()
	defer p.Unlock()

	elem := p.head
	for elem != nil {
		next := elem.next
		elem.conn.Close()
		putPoolElem(elem)
		elem = next
	}
	qnty := p.qnty
	p.qnty = 0
	p.head = nil
	p.tail = nil

	return qnty
}

// hostnameTo
type hostnameTo[T Component] struct {
	hostname []byte // "example.com" for exact map, ".example.com" for suffix map, "www.example." for prefix map
	target   T      // service or webapp
}

// tempFile is used to temporarily save incoming content in local file system.
type tempFile interface {
	Name() string // used by os.Remove()
	Write(src []byte) (n int, err error)
	Seek(offset int64, whence int) (ret int64, err error)
	Close() error
}

// varKeeper holdes values of variables.
type varKeeper interface {
	riskyVariable(varCode int16, varName string) (varValue []byte)
}

var varCodes = map[string]int16{ // TODO
	// general conn vars for quix, tcpx, and udpx
	"srcHost": 0,
	"srcPort": 1,
	"udsMode": 2,
	"tlsMode": 3,

	// quix conn vars

	// tcpx conn vars
	"serverName": 4,
	"nextProto":  5,

	// udpx conn vars

	// http request vars
	"method":      0, // GET, POST, ...
	"scheme":      1, // http, https
	"authority":   2, // example.com, example.org:8080
	"hostname":    3, // example.com, example.org
	"colonport":   4, // :80, :8080
	"path":        5, // /abc, /def/
	"uri":         6, // /abc?x=y, /%cc%dd?y=z&z=%ff
	"encodedPath": 7, // /abc, /%cc%dd
	"queryString": 8, // ?x=y, ?y=z&z=%ff, ?z
	"contentType": 9, // application/json
}

// fakeFile
var fakeFile _fakeFile

// _fakeFile implements tempFile.
type _fakeFile struct{}

func (f _fakeFile) Name() string                           { return "" }
func (f _fakeFile) Write(src []byte) (n int, err error)    { return }
func (f _fakeFile) Seek(int64, int) (ret int64, err error) { return }
func (f _fakeFile) Close() error                           { return nil }

const ( // array kinds
	arrayKindStock = iota // refers to stock buffer. must be 0
	arrayKindPool         // got from sync.Pool
	arrayKindMake         // made from make([]byte)
)

var ( // defined errors
	errNodeDown = errors.New("node is down")
	errNodeBusy = errors.New("node is busy")
)

const ( // units
	K = 1 << 10
	M = 1 << 20
	G = 1 << 30
	T = 1 << 40
)

const ( // sizes
	_1K   = 1 * K    // mostly used by stock buffers
	_4K   = 4 * K    // mostly used by pooled buffers
	_16K  = 16 * K   // mostly used by pooled buffers
	_64K1 = 64*K - 1 // mostly used by pooled buffers

	_128K = 128 * K
	_256K = 256 * K
	_512K = 512 * K
	_1M   = 1 * M
	_2M   = 2 * M
	_4M   = 4 * M
	_8M   = 8 * M
	_16M  = 16 * M
	_32M  = 32 * M
	_64M  = 64 * M
	_128M = 128 * M
	_256M = 256 * M
	_512M = 512 * M
	_1G   = 1 * G
	_2G1  = 2*G - 1 // suitable for max int32 [-2147483648, 2147483647]

	_1T = 1 * T
)

var ( // pools
	pool4K   sync.Pool
	pool16K  sync.Pool
	pool64K1 sync.Pool
)

func Get4K() []byte   { return getNK(&pool4K, _4K) }
func Get16K() []byte  { return getNK(&pool16K, _16K) }
func Get64K1() []byte { return getNK(&pool64K1, _64K1) }
func GetNK(n int64) []byte {
	if n <= _4K {
		return getNK(&pool4K, _4K)
	} else if n <= _16K {
		return getNK(&pool16K, _16K)
	} else { // n > _16K
		return getNK(&pool64K1, _64K1)
	}
}
func getNK(pool *sync.Pool, size int) []byte {
	if x := pool.Get(); x != nil {
		return x.([]byte)
	}
	return make([]byte, size)
}
func PutNK(p []byte) {
	switch cap(p) {
	case _4K:
		pool4K.Put(p)
	case _16K:
		pool16K.Put(p)
	case _64K1:
		pool64K1.Put(p)
	default:
		BugExitln("bad buffer")
	}
}

func makeTempName(dst []byte, stageID int32, unixTime int64, connID int64, counter int64) int {
	// TODO: improvement
	// stageID(8) | unixTime(24) | connID(16) | counter(16)
	stageID &= 0x7f
	unixTime &= 0xffffff
	connID &= 0xffff
	counter &= 0xffff
	return i64ToDec(int64(stageID)<<56|unixTime<<32|connID<<16|counter, dst)
}

func equalMatch(value []byte, patterns [][]byte) bool {
	for _, pattern := range patterns {
		if bytes.Equal(value, pattern) {
			return true
		}
	}
	return false
}
func prefixMatch(value []byte, patterns [][]byte) bool {
	for _, pattern := range patterns {
		if bytes.HasPrefix(value, pattern) {
			return true
		}
	}
	return false
}
func suffixMatch(value []byte, patterns [][]byte) bool {
	for _, pattern := range patterns {
		if bytes.HasSuffix(value, pattern) {
			return true
		}
	}
	return false
}
func containMatch(value []byte, patterns [][]byte) bool {
	for _, pattern := range patterns {
		if bytes.Contains(value, pattern) {
			return true
		}
	}
	return false
}
func regexpMatch(value []byte, regexps []*regexp.Regexp) bool {
	for _, regexp := range regexps {
		if regexp.Match(value) {
			return true
		}
	}
	return false
}
func notEqualMatch(value []byte, patterns [][]byte) bool {
	for _, pattern := range patterns {
		if bytes.Equal(value, pattern) {
			return false
		}
	}
	return true
}
func notPrefixMatch(value []byte, patterns [][]byte) bool {
	for _, pattern := range patterns {
		if bytes.HasPrefix(value, pattern) {
			return false
		}
	}
	return true
}
func notSuffixMatch(value []byte, patterns [][]byte) bool {
	for _, pattern := range patterns {
		if bytes.HasSuffix(value, pattern) {
			return false
		}
	}
	return true
}
func notContainMatch(value []byte, patterns [][]byte) bool {
	for _, pattern := range patterns {
		if bytes.Contains(value, pattern) {
			return false
		}
	}
	return true
}
func notRegexpMatch(value []byte, regexps []*regexp.Regexp) bool {
	for _, regexp := range regexps {
		if regexp.Match(value) {
			return false
		}
	}
	return true
}
