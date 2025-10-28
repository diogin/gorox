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

// Service is the RPC service.
type Service struct {
	// Parent
	Component_
	// Mixins
	_accessLogger_ // services can log accesses
	// Assocs
	stage   *Stage        // current stage
	servers []*hrpcServer // bound hrpc servers. may be empty
	// States
	hostnames       [][]byte           // ...
	maxContentSize  int64              // max content size allowed
	exactHostnames  [][]byte           // like: ("example.com")
	suffixHostnames [][]byte           // like: ("*.example.com")
	prefixHostnames [][]byte           // like: ("www.example.*")
	bundlets        map[string]Bundlet // ...
}

func (s *Service) onCreate(compName string, stage *Stage) {
	s.MakeComp(compName)
	s.stage = stage
}
func (s *Service) OnShutdown() { close(s.ShutChan) } // notifies maintain() which shutdown sub components

func (s *Service) OnConfigure() {
	s._accessLogger_.onConfigure(s)

	// .maxContentSize
	s.ConfigureInt64("maxContentSize", &s.maxContentSize, func(value int64) error {
		if value > 0 && value <= _1G {
			return nil
		}
		return errors.New(".maxContentSize has an invalid value")
	}, _16M)
}
func (s *Service) OnPrepare() {
	s._accessLogger_.onPrepare(s)

	initsLock.RLock()
	serviceInit := serviceInits[s.compName]
	initsLock.RUnlock()
	if serviceInit != nil {
		if err := serviceInit(s); err != nil {
			UseExitln(err.Error())
		}
	}
}

func (s *Service) maintain() { // runner
	s.LoopRun(time.Second, func(now time.Time) {
		// TODO
	})
	s.CloseLog()
	if DebugLevel() >= 2 {
		Printf("service=%s done\n", s.CompName())
	}
	s.stage.DecService()
}

func (s *Service) bindServer(server *hrpcServer) { s.servers = append(s.servers, server) }

/*
func (s *Service) dispatch(call) {
	// TODO
}
*/

// Bundlet is a collection of related procedures in a service. A service has many bundlets.
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
	defaultService *Service // default service if not found
	// States
	services                  []string                // for what services
	exactServices             []*hostnameTo[*Service] // like: ("example.com")
	suffixServices            []*hostnameTo[*Service] // like: ("*.example.com")
	prefixServices            []*hostnameTo[*Service] // like: ("www.example.*")
	recvTimeout               time.Duration           // timeout to recv the whole message content. zero means no timeout
	sendTimeout               time.Duration           // timeout to send the whole message. zero means no timeout
	maxConcurrentConnsPerGate int32                   // max concurrent connections allowed per gate
}

func (s *hrpcServer) onCreate(compName string, stage *Stage) {
	s.Server_.OnCreate(compName, stage)
}

func (s *hrpcServer) OnConfigure() {
	s.Server_.OnConfigure()
	s._hrpcHolder_.onConfigure(s)

	// .services
	s.ConfigureStringList("services", &s.services, nil, []string{})

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

func (s *hrpcServer) bindServices() {
	for _, serviceName := range s.services {
		service := s.stage.Service(serviceName)
		if service == nil {
			continue
		}
		service.bindServer(s)
		// TODO: use hash table?
		for _, hostname := range service.exactHostnames {
			s.exactServices = append(s.exactServices, &hostnameTo[*Service]{hostname, service})
		}
		// TODO: use radix trie?
		for _, hostname := range service.suffixHostnames {
			s.suffixServices = append(s.suffixServices, &hostnameTo[*Service]{hostname, service})
		}
		// TODO: use radix trie?
		for _, hostname := range service.prefixHostnames {
			s.prefixServices = append(s.prefixServices, &hostnameTo[*Service]{hostname, service})
		}
	}
}
func (s *hrpcServer) findService(hostname []byte) *Service {
	// TODO: use hash table?
	for _, exactMap := range s.exactServices {
		if bytes.Equal(hostname, exactMap.hostname) {
			return exactMap.target
		}
	}
	// TODO: use radix trie?
	for _, suffixMap := range s.suffixServices {
		if bytes.HasSuffix(hostname, suffixMap.hostname) {
			return suffixMap.target
		}
	}
	// TODO: use radix trie?
	for _, prefixMap := range s.prefixServices {
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
