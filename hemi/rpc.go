// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// HRPC Framework implementation.

// HRPC is a request/response RPC protocol designed for IDC.
// HRPC is under design, its transport protocol is not determined. Maybe we can build it upon HTTP/3 without TLS?

package hemi

import (
	"bytes"
	"errors"
	"sync/atomic"
	"time"
)

// Rpcsvc is the RPC service.
type Rpcsvc struct {
	// Parent
	Component_
	// Mixins
	_accessLogger_ // rpcsvcs can log accesses
	// Assocs
	stage   *Stage        // current stage
	servers []*hrpcServer // bound hrpc servers. may be empty
	// States
	hostnames       [][]byte           // ...
	exactHostnames  [][]byte           // like: ("example.com")
	suffixHostnames [][]byte           // like: ("*.example.com")
	prefixHostnames [][]byte           // like: ("www.example.*")
	maxContentSize  int64              // max content size allowed
	bundlets        map[string]Bundlet // registered bundlets. indexed by name
}

func (s *Rpcsvc) onCreate(compName string, stage *Stage) {
	s.MakeComp(compName)
	s.stage = stage
}
func (s *Rpcsvc) OnShutdown() { close(s.ShutChan) } // notifies maintain() which shutdown sub components

func (s *Rpcsvc) OnConfigure() {
	s._accessLogger_.onConfigure(s)

	// .maxContentSize
	s.ConfigureInt64("maxContentSize", &s.maxContentSize, func(value int64) error {
		if value > 0 && value <= _1G {
			return nil
		}
		return errors.New(".maxContentSize has an invalid value")
	}, _16M)
}
func (s *Rpcsvc) OnPrepare() {
	s._accessLogger_.onPrepare(s)

	initsLock.RLock()
	rpcsvcInit := rpcsvcInits[s.compName]
	initsLock.RUnlock()
	if rpcsvcInit != nil {
		if err := rpcsvcInit(s); err != nil {
			UseExitln(err.Error())
		}
	}
}

func (s *Rpcsvc) maintain() { // runner
	s.LoopRun(time.Second, func(now time.Time) {
		// TODO
	})
	s.CloseLog()
	if DebugLevel() >= 2 {
		Printf("rpcsvc=%s done\n", s.CompName())
	}
	s.stage.DecRpcsvc()
}

func (s *Rpcsvc) RegisterBundlet(name string, bundlet Bundlet) {
	if s.bundlets[name] != nil {
		UseExitln("conflicting bundlet with a same name in rpcsvc")
	}
	s.bundlets[name] = bundlet
}

func (s *Rpcsvc) bindServer(server *hrpcServer) { s.servers = append(s.servers, server) }

func (s *Rpcsvc) dispatchCall(call *hrpcCall) {
	// TODO
}

// Bundlet is a collection of related procedures in an rpcsvc. An rpcsvc has many bundlets.
// Bundlets are not components.
type Bundlet interface {
}

// Bundlet_ is a parent.
type Bundlet_ struct { // for all bundlets
}

/*
func (b *Bundlet_) dispatch(call) {
}
*/

////////////////////////////////////////////////////////////////////////////////

// _hrpcHolder_
type _hrpcHolder_ struct { // for hrpcServer, hrpcGate, and hrpcClient
}

func (h *_hrpcHolder_) onConfigure(comp Component) {
}
func (h *_hrpcHolder_) onPrepare(comp Component) {
}

// rpcConn_ is a parent.
type rpcConn_ struct { // for hrpcConn and hConn
	// TODO
}

// rpcCall_ is a parent.
type rpcCall_ struct { // for hrpcCall and hCall
	// request
	// response
}

////////////////////////////////////////////////////////////////////////////////

func init() {
	RegisterServer("hrpcServer", func(compName string, stage *Stage) Server {
		s := new(hrpcServer)
		s.onCreate(compName, stage)
		return s
	})
}

// hrpcServer is the HRPC server. An hrpcServer has many hrpcGates.
type hrpcServer struct {
	// Parent
	Server_[*hrpcGate]
	// Mixins
	_hrpcHolder_ // to carry configs used by gates
	// Assocs
	defaultRpcsvc *Rpcsvc // default rpcsvc if not found
	// States
	rpcsvcs                   []string               // for what rpcsvcs
	exactRpcsvcs              []*hostnameTo[*Rpcsvc] // like: ("example.com")
	suffixRpcsvcs             []*hostnameTo[*Rpcsvc] // like: ("*.example.com")
	prefixRpcsvcs             []*hostnameTo[*Rpcsvc] // like: ("www.example.*")
	recvTimeout               time.Duration          // timeout to recv the whole message content. zero means no timeout
	sendTimeout               time.Duration          // timeout to send the whole message. zero means no timeout
	maxConcurrentConnsPerGate int32                  // max concurrent connections allowed per gate
}

func (s *hrpcServer) onCreate(compName string, stage *Stage) {
	s.Server_.OnCreate(compName, stage)
}

func (s *hrpcServer) OnConfigure() {
	s.Server_.OnConfigure()
	s._hrpcHolder_.onConfigure(s)

	// .rpcsvcs
	s.ConfigureStringList("rpcsvcs", &s.rpcsvcs, nil, []string{})

	// .recvTimeout
	s.ConfigureDuration("recvTimeout", &s.recvTimeout, func(value time.Duration) error {
		if value >= 0 {
			return nil
		}
		return errors.New(".recvTimeout has an invalid value")
	}, 60*time.Second)

	// .sendTimeout
	s.ConfigureDuration("sendTimeout", &s.sendTimeout, func(value time.Duration) error {
		if value >= 0 {
			return nil
		}
		return errors.New(".sendTimeout has an invalid value")
	}, 60*time.Second)

	// .maxConcurrentConnsPerGate
	s.ConfigureInt32("maxConcurrentConnsPerGate", &s.maxConcurrentConnsPerGate, func(value int32) error {
		if value > 0 {
			return nil
		}
		return errors.New(".maxConcurrentConnsPerGate has an invalid value")
	}, 10000)
}
func (s *hrpcServer) OnPrepare() {
	s.Server_.OnPrepare()
	s._hrpcHolder_.onPrepare(s)
}

func (s *hrpcServer) MaxConcurrentConnsPerGate() int32 { return s.maxConcurrentConnsPerGate }

func (s *hrpcServer) bindRpcsvcs() {
	for _, rpcsvcName := range s.rpcsvcs {
		rpcsvc := s.stage.Rpcsvc(rpcsvcName)
		if rpcsvc == nil {
			continue
		}
		rpcsvc.bindServer(s)
		// TODO: use hash table?
		for _, hostname := range rpcsvc.exactHostnames {
			s.exactRpcsvcs = append(s.exactRpcsvcs, &hostnameTo[*Rpcsvc]{hostname, rpcsvc})
		}
		// TODO: use radix trie?
		for _, hostname := range rpcsvc.suffixHostnames {
			s.suffixRpcsvcs = append(s.suffixRpcsvcs, &hostnameTo[*Rpcsvc]{hostname, rpcsvc})
		}
		// TODO: use radix trie?
		for _, hostname := range rpcsvc.prefixHostnames {
			s.prefixRpcsvcs = append(s.prefixRpcsvcs, &hostnameTo[*Rpcsvc]{hostname, rpcsvc})
		}
	}
}
func (s *hrpcServer) findRpcsvc(hostname []byte) *Rpcsvc {
	// TODO: use hash table?
	for _, exactMap := range s.exactRpcsvcs {
		if bytes.Equal(hostname, exactMap.hostname) {
			return exactMap.target
		}
	}
	// TODO: use radix trie?
	for _, suffixMap := range s.suffixRpcsvcs {
		if bytes.HasSuffix(hostname, suffixMap.hostname) {
			return suffixMap.target
		}
	}
	// TODO: use radix trie?
	for _, prefixMap := range s.prefixRpcsvcs {
		if bytes.HasPrefix(hostname, prefixMap.hostname) {
			return prefixMap.target
		}
	}
	return nil
}

func (s *hrpcServer) Serve() { // runner
	// TODO
}

func (s *hrpcServer) hrpcHolder() _hrpcHolder_ { return s._hrpcHolder_ }

// hrpcGate is a gate of hrpcServer.
type hrpcGate struct {
	// Parent
	Gate_[*hrpcServer]
	// Mixins
	_hrpcHolder_
	// States
	maxConcurrentConns int32
	concurrentConns    atomic.Int32
}

func (g *hrpcGate) onNew(server *hrpcServer, id int32) {
	g.Gate_.OnNew(server, id)
	g._hrpcHolder_ = server.hrpcHolder()
	g.maxConcurrentConns = server.MaxConcurrentConnsPerGate()
}

func (g *hrpcGate) Open() error {
	// TODO
	return nil
}
func (g *hrpcGate) Shut() error {
	g.MarkShut()
	// TODO // breaks serve()
	return nil
}

func (g *hrpcGate) Serve() { // runner
	// TODO
}

// hrpcConn
type hrpcConn struct {
	// Parent
	rpcConn_
	// States
	id      int64 // the conn id
	gate    *hrpcGate
	counter atomic.Int64 // can be used to generate a random number
}

func (c *hrpcConn) onGet(id int64, gate *hrpcGate) {
	c.id = id
	c.gate = gate
}
func (c *hrpcConn) onPut() {
	c.gate = nil
	c.counter.Store(0)
}

func (c *hrpcConn) MakeTempName(dst []byte, unixTime int64) int {
	return makeTempName(dst, c.gate.Stage().ID(), unixTime, c.id, c.counter.Add(1))
}

// hrpcCall
type hrpcCall struct {
	// Parent
	rpcCall_
	// States
}

////////////////////////////////////////////////////////////////////////////////

// hrpcClient
type hrpcClient struct {
	// TODO
}

// hConn
type hConn struct {
	// Parent
	rpcConn_
	// States
}

// hCall
type hCall struct {
	// Parent
	rpcCall_
	// States
}
