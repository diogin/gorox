// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// Basic elements that exist between multiple stages.

package hemi

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const Version = "0.3.0"

var (
	_develMode  atomic.Bool  // running in developer mode?
	_debugLevel atomic.Int32 // the more of the level, the more verbose
	_topDir     atomic.Value // directory of the executable
	_topOnce    sync.Once    // protects _topDir
	_logDir     atomic.Value // directory of the log files
	_logOnce    sync.Once    // protects _logDir
	_tmpDir     atomic.Value // directory of the temp files
	_tmpOnce    sync.Once    // protects _tmpDir
	_varDir     atomic.Value // directory of the run-time data
	_varOnce    sync.Once    // protects _varDir
)

func DevelMode() bool   { return _develMode.Load() }
func DebugLevel() int32 { return _debugLevel.Load() }
func TopDir() string    { return _topDir.Load().(string) }
func LogDir() string    { return _logDir.Load().(string) }
func TmpDir() string    { return _tmpDir.Load().(string) }
func VarDir() string    { return _varDir.Load().(string) }

func SetDevelMode(devel bool)   { _develMode.Store(devel) }
func SetDebugLevel(level int32) { _debugLevel.Store(level) }
func SetTopDir(dir string) { // only once!
	_topOnce.Do(func() {
		_topDir.Store(dir)
	})
}
func SetLogDir(dir string) { // only once!
	_logOnce.Do(func() {
		_logDir.Store(dir)
		_mustMkdir(dir)
	})
}
func SetTmpDir(dir string) { // only once!
	_tmpOnce.Do(func() {
		_tmpDir.Store(dir)
		_mustMkdir(dir)
	})
}
func SetVarDir(dir string) { // only once!
	_varOnce.Do(func() {
		_varDir.Store(dir)
		_mustMkdir(dir)
	})
}
func _mustMkdir(dir string) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(0)
	}
}

func StageFromText(configText string) (*Stage, error) {
	_checkDirs()
	var c configurator
	return c.stageFromText(configText)
}
func StageFromFile(configBase string, configFile string) (*Stage, error) {
	_checkDirs()
	var c configurator
	return c.stageFromFile(configBase, configFile)
}
func _checkDirs() {
	if _topDir.Load() == nil || _logDir.Load() == nil || _tmpDir.Load() == nil || _varDir.Load() == nil {
		UseExitln("topDir, logDir, tmpDir, and varDir must all be set!")
	}
}

const ( // exit codes
	CodeBug = 20
	CodeUse = 21
	CodeEnv = 22
)

func BugExitln(v ...any)          { _exitln(CodeBug, "[BUG] ", v...) }
func BugExitf(f string, v ...any) { _exitf(CodeBug, "[BUG] ", f, v...) }
func UseExitln(v ...any)          { _exitln(CodeUse, "[USE] ", v...) }
func UseExitf(f string, v ...any) { _exitf(CodeUse, "[USE] ", f, v...) }
func EnvExitln(v ...any)          { _exitln(CodeEnv, "[ENV] ", v...) }
func EnvExitf(f string, v ...any) { _exitf(CodeEnv, "[ENV] ", f, v...) }
func _exitln(exitCode int, prefix string, v ...any) {
	fmt.Fprint(os.Stderr, prefix)
	fmt.Fprintln(os.Stderr, v...)
	os.Exit(exitCode)
}
func _exitf(exitCode int, prefix, f string, v ...any) {
	fmt.Fprintf(os.Stderr, prefix+f, v...)
	os.Exit(exitCode)
}

////////////////////////////////////////////////////////////////////////////////

const ( // list of component types
	compTypeStage int16 = 1 + iota
	compTypeFixture
	compTypeBackend
	compTypeNode
	compTypeRpcsvc
	compTypeHstate
	compTypeHcache
	compTypeWebapp
	compTypeRule
	compTypeHandlet
	compTypeSocklet
	compTypeQUIXRouter
	compTypeTCPXRouter
	compTypeUDPXRouter
	compTypeCase
	compTypeQUIXDealet
	compTypeTCPXDealet
	compTypeUDPXDealet
	compTypeServer
	compTypeCronjob
)

var signedComps = map[string]int16{ // signed comps. more dynamic comps are signed using _signComp() below
	"stage":      compTypeStage,
	"node":       compTypeNode,
	"rpcsvc":     compTypeRpcsvc,
	"webapp":     compTypeWebapp,
	"rule":       compTypeRule,
	"quixRouter": compTypeQUIXRouter,
	"tcpxRouter": compTypeTCPXRouter,
	"udpxRouter": compTypeUDPXRouter,
	"case":       compTypeCase,
}

func _signComp(compSign string, compType int16) {
	if signedType, ok := signedComps[compSign]; ok {
		BugExitf("conflicting component sign: compType=%d compSign=%s\n", signedType, compSign)
	}
	signedComps[compSign] = compType
}

var fixtureSigns = make(map[string]bool) // we guarantee this is not manipulated concurrently, so no lock is required

func registerFixture(compSign string) {
	if _, ok := fixtureSigns[compSign]; ok {
		BugExitln("fixture sign conflicted")
	}
	fixtureSigns[compSign] = true
	_signComp(compSign, compTypeFixture)
}

var ( // component creators
	creatorsLock       sync.RWMutex
	backendCreators    = make(map[string]func(compName string, stage *Stage) Backend) // indexed by compSign, same below.
	hstateCreators     = make(map[string]func(compName string, stage *Stage) Hstate)
	hcacheCreators     = make(map[string]func(compName string, stage *Stage) Hcache)
	handletCreators    = make(map[string]func(compName string, stage *Stage, webapp *Webapp) Handlet)
	sockletCreators    = make(map[string]func(compName string, stage *Stage, webapp *Webapp) Socklet)
	quixDealetCreators = make(map[string]func(compName string, stage *Stage, router *QUIXRouter) QUIXDealet)
	tcpxDealetCreators = make(map[string]func(compName string, stage *Stage, router *TCPXRouter) TCPXDealet)
	udpxDealetCreators = make(map[string]func(compName string, stage *Stage, router *UDPXRouter) UDPXDealet)
	serverCreators     = make(map[string]func(compName string, stage *Stage) Server)
	cronjobCreators    = make(map[string]func(compName string, stage *Stage) Cronjob)
)

func RegisterBackend(compSign string, create func(compName string, stage *Stage) Backend) {
	_registerComponent0(compSign, compTypeBackend, backendCreators, create)
}
func RegisterHstate(compSign string, create func(compName string, stage *Stage) Hstate) {
	_registerComponent0(compSign, compTypeHstate, hstateCreators, create)
}
func RegisterHcache(compSign string, create func(compName string, stage *Stage) Hcache) {
	_registerComponent0(compSign, compTypeHcache, hcacheCreators, create)
}
func RegisterServer(compSign string, create func(compName string, stage *Stage) Server) {
	_registerComponent0(compSign, compTypeServer, serverCreators, create)
}
func RegisterCronjob(compSign string, create func(compName string, stage *Stage) Cronjob) {
	_registerComponent0(compSign, compTypeCronjob, cronjobCreators, create)
}
func _registerComponent0[T Component](compSign string, compType int16, creators map[string]func(string, *Stage) T, create func(string, *Stage) T) { // backend, hstate, hcache, server, cronjob
	creatorsLock.Lock()
	defer creatorsLock.Unlock()

	if _, ok := creators[compSign]; ok {
		BugExitln("component0 sign conflicted")
	}
	creators[compSign] = create
	_signComp(compSign, compType)
}

func RegisterHandlet(compSign string, create func(compName string, stage *Stage, webapp *Webapp) Handlet) {
	_registerComponent1(compSign, compTypeHandlet, handletCreators, create)
}
func RegisterSocklet(compSign string, create func(compName string, stage *Stage, webapp *Webapp) Socklet) {
	_registerComponent1(compSign, compTypeSocklet, sockletCreators, create)
}
func RegisterQUIXDealet(compSign string, create func(compName string, stage *Stage, router *QUIXRouter) QUIXDealet) {
	_registerComponent1(compSign, compTypeQUIXDealet, quixDealetCreators, create)
}
func RegisterTCPXDealet(compSign string, create func(compName string, stage *Stage, router *TCPXRouter) TCPXDealet) {
	_registerComponent1(compSign, compTypeTCPXDealet, tcpxDealetCreators, create)
}
func RegisterUDPXDealet(compSign string, create func(compName string, stage *Stage, router *UDPXRouter) UDPXDealet) {
	_registerComponent1(compSign, compTypeUDPXDealet, udpxDealetCreators, create)
}
func _registerComponent1[T Component, C Component](compSign string, compType int16, creators map[string]func(string, *Stage, C) T, create func(string, *Stage, C) T) { // handlet, socklet, dealet
	creatorsLock.Lock()
	defer creatorsLock.Unlock()

	if _, ok := creators[compSign]; ok {
		BugExitln("component1 sign conflicted")
	}
	creators[compSign] = create
	_signComp(compSign, compType)
}

var ( // initializers of rpcsvcs & webapps
	initsLock   sync.RWMutex
	rpcsvcInits = make(map[string]func(rpcsvc *Rpcsvc) error) // indexed by compName, same below.
	webappInits = make(map[string]func(webapp *Webapp) error)
)

func RegisterRpcsvcInit(rpcsvcName string, init func(rpcsvc *Rpcsvc) error) {
	initsLock.Lock()
	rpcsvcInits[rpcsvcName] = init
	initsLock.Unlock()
}
func RegisterWebappInit(webappName string, init func(webapp *Webapp) error) {
	initsLock.Lock()
	webappInits[webappName] = init
	initsLock.Unlock()
}

////////////////////////////////////////////////////////////////////////////////

// Component is the interface for all components.
type Component interface {
	MakeComp(compName string)
	CompName() string

	OnShutdown()

	OnConfigure()
	Find(propName string) (propValue Value, ok bool)
	Prop(propName string) (propValue Value, ok bool)
	ConfigureBool(propName string, prop *bool, defaultValue bool)
	ConfigureInt64(propName string, prop *int64, check func(value int64) error, defaultValue int64)
	ConfigureInt32(propName string, prop *int32, check func(value int32) error, defaultValue int32)
	ConfigureInt16(propName string, prop *int16, check func(value int16) error, defaultValue int16)
	ConfigureInt8(propName string, prop *int8, check func(value int8) error, defaultValue int8)
	ConfigureInt(propName string, prop *int, check func(value int) error, defaultValue int)
	ConfigureString(propName string, prop *string, check func(value string) error, defaultValue string)
	ConfigureBytes(propName string, prop *[]byte, check func(value []byte) error, defaultValue []byte)
	ConfigureDuration(propName string, prop *time.Duration, check func(value time.Duration) error, defaultValue time.Duration)
	ConfigureStringList(propName string, prop *[]string, check func(value []string) error, defaultValue []string)
	ConfigureBytesList(propName string, prop *[][]byte, check func(value [][]byte) error, defaultValue [][]byte)
	ConfigureStringDict(propName string, prop *map[string]string, check func(value map[string]string) error, defaultValue map[string]string)

	OnPrepare()

	setName(compName string)
	setShell(shell Component)
	setParent(parent Component)
	setInfo(info any)
	setProp(propName string, propValue Value)

	getParent() Component
}

// Component_ is a parent.
type Component_ struct { // for all components
	// Assocs
	shell  Component // the concrete Component
	parent Component // the parent component, used by configurator
	// States
	compName string           // main, proxy1, ...
	props    map[string]Value // name1=value1, ...
	ShutChan chan struct{}    // used to notify the component to shutdown
	subs     sync.WaitGroup   // sub components/objects to wait for
	info     any              // hold extra info about this component, used by configurator
}

func (c *Component_) MakeComp(compName string) {
	c.compName = compName
	c.props = make(map[string]Value)
	c.ShutChan = make(chan struct{})
}
func (c *Component_) CompName() string { return c.compName }

func (c *Component_) Find(propName string) (propValue Value, ok bool) {
	for component := c.shell; component != nil; component = component.getParent() {
		if propValue, ok = component.Prop(propName); ok {
			break
		}
	}
	return
}
func (c *Component_) Prop(propName string) (propValue Value, ok bool) {
	propValue, ok = c.props[propName]
	return
}

func (c *Component_) ConfigureBool(propName string, prop *bool, defaultValue bool) {
	_configureProp(c, propName, prop, (*Value).Bool, nil, defaultValue)
}
func (c *Component_) ConfigureInt64(propName string, prop *int64, check func(value int64) error, defaultValue int64) {
	_configureProp(c, propName, prop, (*Value).Int64, check, defaultValue)
}
func (c *Component_) ConfigureInt32(propName string, prop *int32, check func(value int32) error, defaultValue int32) {
	_configureProp(c, propName, prop, (*Value).Int32, check, defaultValue)
}
func (c *Component_) ConfigureInt16(propName string, prop *int16, check func(value int16) error, defaultValue int16) {
	_configureProp(c, propName, prop, (*Value).Int16, check, defaultValue)
}
func (c *Component_) ConfigureInt8(propName string, prop *int8, check func(value int8) error, defaultValue int8) {
	_configureProp(c, propName, prop, (*Value).Int8, check, defaultValue)
}
func (c *Component_) ConfigureInt(propName string, prop *int, check func(value int) error, defaultValue int) {
	_configureProp(c, propName, prop, (*Value).Int, check, defaultValue)
}
func (c *Component_) ConfigureString(propName string, prop *string, check func(value string) error, defaultValue string) {
	_configureProp(c, propName, prop, (*Value).String, check, defaultValue)
}
func (c *Component_) ConfigureBytes(propName string, prop *[]byte, check func(value []byte) error, defaultValue []byte) {
	_configureProp(c, propName, prop, (*Value).Bytes, check, defaultValue)
}
func (c *Component_) ConfigureDuration(propName string, prop *time.Duration, check func(value time.Duration) error, defaultValue time.Duration) {
	_configureProp(c, propName, prop, (*Value).Duration, check, defaultValue)
}
func (c *Component_) ConfigureStringList(propName string, prop *[]string, check func(value []string) error, defaultValue []string) {
	_configureProp(c, propName, prop, (*Value).StringList, check, defaultValue)
}
func (c *Component_) ConfigureBytesList(propName string, prop *[][]byte, check func(value [][]byte) error, defaultValue [][]byte) {
	_configureProp(c, propName, prop, (*Value).BytesList, check, defaultValue)
}
func (c *Component_) ConfigureStringDict(propName string, prop *map[string]string, check func(value map[string]string) error, defaultValue map[string]string) {
	_configureProp(c, propName, prop, (*Value).StringDict, check, defaultValue)
}
func _configureProp[T any](c *Component_, propName string, prop *T, conv func(*Value) (T, bool), check func(value T) error, defaultValue T) {
	if propValue, ok := c.Find(propName); ok {
		if value, ok := conv(&propValue); ok && check == nil {
			*prop = value
		} else if ok && check != nil {
			if err := check(value); err == nil {
				*prop = value
			} else {
				// TODO: line number
				UseExitln(fmt.Sprintf("%s is error in %s: %s", propName, c.compName, err.Error()))
			}
		} else {
			UseExitln(fmt.Sprintf("invalid %s in %s", propName, c.compName))
		}
	} else { // not found. use default value
		*prop = defaultValue
	}
}

func (c *Component_) LoopRun(interval time.Duration, callback func(now time.Time)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ShutChan:
			return
		case now := <-ticker.C:
			callback(now)
		}
	}
}

func (c *Component_) setShell(shell Component)                 { c.shell = shell }
func (c *Component_) setParent(parent Component)               { c.parent = parent }
func (c *Component_) setName(compName string)                  { c.compName = compName }
func (c *Component_) setProp(propName string, propValue Value) { c.props[propName] = propValue }
func (c *Component_) setInfo(info any)                         { c.info = info }

func (c *Component_) getParent() Component { return c.parent }

// compDict
type compDict[T Component] map[string]T

func (d compDict[T]) walk(method func(T)) {
	for _, component := range d {
		method(component)
	}
}
func (d compDict[T]) goWalk(method func(T)) {
	for _, component := range d {
		go method(component)
	}
}

////////////////////////////////////////////////////////////////////////////////

// Stage component represents a running stage in the engine.
//
// The engine may have many stages during its lifetime, especially when new
// configuration is applied, a new stage is created, or the old one is told to quit.
type Stage struct {
	// Parent
	Component_
	// Assocs
	clock       *clockFixture         // for fast accessing
	fcache      *fcacheFixture        // for fast accessing
	resolv      *resolvFixture        // for fast accessing
	fixtures    compDict[fixture]     // indexed by compSign
	backends    compDict[Backend]     // indexed by compName
	rpcsvcs     compDict[*Rpcsvc]     // indexed by compName
	hstates     compDict[Hstate]      // indexed by compName
	hcaches     compDict[Hcache]      // indexed by compName
	webapps     compDict[*Webapp]     // indexed by compName
	quixRouters compDict[*QUIXRouter] // indexed by compName
	tcpxRouters compDict[*TCPXRouter] // indexed by compName
	udpxRouters compDict[*UDPXRouter] // indexed by compName
	servers     compDict[Server]      // indexed by compName
	cronjobs    compDict[Cronjob]     // indexed by compName
	// States
	id      int32
	numCPU  int
	cpuFile string
	hepFile string
	thrFile string
	grtFile string
	blkFile string
}

// createStage creates a new stage which runs alongside existing stages.
func createStage() *Stage {
	stage := new(Stage)
	stage.onCreate()
	stage.setShell(stage)
	return stage
}

func (s *Stage) onCreate() {
	s.MakeComp("stage")

	s.clock = createClock(s)
	s.fcache = createFcache(s)
	s.resolv = createResolv(s)
	s.fixtures = make(compDict[fixture])
	s.fixtures[signClock] = s.clock
	s.fixtures[signFcache] = s.fcache
	s.fixtures[signResolv] = s.resolv

	s.backends = make(compDict[Backend])
	s.rpcsvcs = make(compDict[*Rpcsvc])
	s.hstates = make(compDict[Hstate])
	s.hcaches = make(compDict[Hcache])
	s.webapps = make(compDict[*Webapp])
	s.quixRouters = make(compDict[*QUIXRouter])
	s.tcpxRouters = make(compDict[*TCPXRouter])
	s.udpxRouters = make(compDict[*UDPXRouter])
	s.servers = make(compDict[Server])
	s.cronjobs = make(compDict[Cronjob])
}
func (s *Stage) OnShutdown() {
	if DebugLevel() >= 2 {
		Printf("stage id=%d shutdown start!!\n", s.id)
	}

	// Cronjobs
	s.subs.Add(len(s.cronjobs))
	s.cronjobs.goWalk(Cronjob.OnShutdown)
	s.subs.Wait()

	// Servers
	s.subs.Add(len(s.servers))
	s.servers.goWalk(Server.OnShutdown)
	s.subs.Wait()

	// Routers
	s.subs.Add(len(s.udpxRouters) + len(s.tcpxRouters) + len(s.quixRouters))
	s.udpxRouters.goWalk((*UDPXRouter).OnShutdown)
	s.tcpxRouters.goWalk((*TCPXRouter).OnShutdown)
	s.quixRouters.goWalk((*QUIXRouter).OnShutdown)
	s.subs.Wait()

	// Webapps
	s.subs.Add(len(s.webapps))
	s.webapps.goWalk((*Webapp).OnShutdown)
	s.subs.Wait()

	// Hcaches & Hstates
	s.subs.Add(len(s.hcaches) + len(s.hstates))
	s.hcaches.goWalk(Hcache.OnShutdown)
	s.hstates.goWalk(Hstate.OnShutdown)
	s.subs.Wait()

	// Rpcsvcs
	s.subs.Add(len(s.rpcsvcs))
	s.rpcsvcs.goWalk((*Rpcsvc).OnShutdown)
	s.subs.Wait()

	// Backends
	s.subs.Add(len(s.backends))
	s.backends.goWalk(Backend.OnShutdown)
	s.subs.Wait()

	// Fixtures, manually one by one. Order matters!

	s.subs.Add(1) // fcache
	s.fcache.OnShutdown()
	s.subs.Wait()

	s.subs.Add(1) // resolv
	s.resolv.OnShutdown()
	s.subs.Wait()

	s.subs.Add(1) // clock
	s.clock.OnShutdown()
	s.subs.Wait()

	// Stage
	if DebugLevel() >= 2 {
		// TODO
		Println("stage closed log file")
	}
}

func (s *Stage) OnConfigure() {
	tmpDir := TmpDir()

	// .cpuFile
	s.ConfigureString("cpuFile", &s.cpuFile, func(value string) error {
		if value == "" {
			return errors.New(".cpuFile has an invalid value")
		}
		return nil
	}, tmpDir+"/cpu.prof")

	// .hepFile
	s.ConfigureString("hepFile", &s.hepFile, func(value string) error {
		if value == "" {
			return errors.New(".hepFile has an invalid value")
		}
		return nil
	}, tmpDir+"/hep.prof")

	// .thrFile
	s.ConfigureString("thrFile", &s.thrFile, func(value string) error {
		if value == "" {
			return errors.New(".thrFile has an invalid value")
		}
		return nil
	}, tmpDir+"/thr.prof")

	// .grtFile
	s.ConfigureString("grtFile", &s.grtFile, func(value string) error {
		if value == "" {
			return errors.New(".grtFile has an invalid value")
		}
		return nil
	}, tmpDir+"/grt.prof")

	// .blkFile
	s.ConfigureString("blkFile", &s.blkFile, func(value string) error {
		if value == "" {
			return errors.New(".blkFile has an invalid value")
		}
		return nil
	}, tmpDir+"/blk.prof")

	// sub components
	s.fixtures.walk(fixture.OnConfigure)
	s.backends.walk(Backend.OnConfigure)
	s.rpcsvcs.walk((*Rpcsvc).OnConfigure)
	s.hstates.walk(Hstate.OnConfigure)
	s.hcaches.walk(Hcache.OnConfigure)
	s.webapps.walk((*Webapp).OnConfigure)
	s.quixRouters.walk((*QUIXRouter).OnConfigure)
	s.tcpxRouters.walk((*TCPXRouter).OnConfigure)
	s.udpxRouters.walk((*UDPXRouter).OnConfigure)
	s.servers.walk(Server.OnConfigure)
	s.cronjobs.walk(Cronjob.OnConfigure)
}
func (s *Stage) OnPrepare() {
	for _, file := range []string{s.cpuFile, s.hepFile, s.thrFile, s.grtFile, s.blkFile} {
		if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			EnvExitln(err.Error())
		}
	}

	// sub components
	s.fixtures.walk(fixture.OnPrepare)
	s.backends.walk(Backend.OnPrepare)
	s.rpcsvcs.walk((*Rpcsvc).OnPrepare)
	s.hstates.walk(Hstate.OnPrepare)
	s.hcaches.walk(Hcache.OnPrepare)
	s.webapps.walk((*Webapp).OnPrepare)
	s.quixRouters.walk((*QUIXRouter).OnPrepare)
	s.tcpxRouters.walk((*TCPXRouter).OnPrepare)
	s.udpxRouters.walk((*UDPXRouter).OnPrepare)
	s.servers.walk(Server.OnPrepare)
	s.cronjobs.walk(Cronjob.OnPrepare)
}

func (s *Stage) createBackend(compSign string, compName string) Backend {
	if s.Backend(compName) != nil {
		UseExitf("conflicting backend with a same component name '%s'\n", compName)
	}
	create, ok := backendCreators[compSign]
	if !ok {
		UseExitln("unknown backend type: " + compSign)
	}
	backend := create(compName, s)
	backend.setShell(backend)
	s.backends[compName] = backend
	return backend
}
func (s *Stage) createRpcsvc(compName string) *Rpcsvc {
	if s.Rpcsvc(compName) != nil {
		UseExitf("conflicting rpcsvc with a same component name '%s'\n", compName)
	}
	rpcsvc := new(Rpcsvc)
	rpcsvc.onCreate(compName, s)
	rpcsvc.setShell(rpcsvc)
	s.rpcsvcs[compName] = rpcsvc
	return rpcsvc
}
func (s *Stage) createHstate(compSign string, compName string) Hstate {
	if s.Hstate(compName) != nil {
		UseExitf("conflicting hstate with a same component name '%s'\n", compName)
	}
	create, ok := hstateCreators[compSign]
	if !ok {
		UseExitln("unknown hstate type: " + compSign)
	}
	hstate := create(compName, s)
	hstate.setShell(hstate)
	s.hstates[compName] = hstate
	return hstate
}
func (s *Stage) createHcache(compSign string, compName string) Hcache {
	if s.Hcache(compName) != nil {
		UseExitf("conflicting hcache with a same component name '%s'\n", compName)
	}
	create, ok := hcacheCreators[compSign]
	if !ok {
		UseExitln("unknown hcache type: " + compSign)
	}
	hcache := create(compName, s)
	hcache.setShell(hcache)
	s.hcaches[compName] = hcache
	return hcache
}
func (s *Stage) createWebapp(compName string) *Webapp {
	if s.Webapp(compName) != nil {
		UseExitf("conflicting webapp with a same component name '%s'\n", compName)
	}
	webapp := new(Webapp)
	webapp.onCreate(compName, s)
	webapp.setShell(webapp)
	s.webapps[compName] = webapp
	return webapp
}
func (s *Stage) createQUIXRouter(compName string) *QUIXRouter {
	if s.QUIXRouter(compName) != nil {
		UseExitf("conflicting quixRouter with a same component name '%s'\n", compName)
	}
	router := new(QUIXRouter)
	router.onCreate(compName, s)
	router.setShell(router)
	s.quixRouters[compName] = router
	return router
}
func (s *Stage) createTCPXRouter(compName string) *TCPXRouter {
	if s.TCPXRouter(compName) != nil {
		UseExitf("conflicting tcpxRouter with a same component name '%s'\n", compName)
	}
	router := new(TCPXRouter)
	router.onCreate(compName, s)
	router.setShell(router)
	s.tcpxRouters[compName] = router
	return router
}
func (s *Stage) createUDPXRouter(compName string) *UDPXRouter {
	if s.UDPXRouter(compName) != nil {
		UseExitf("conflicting udpxRouter with a same component name '%s'\n", compName)
	}
	router := new(UDPXRouter)
	router.onCreate(compName, s)
	router.setShell(router)
	s.udpxRouters[compName] = router
	return router
}
func (s *Stage) createServer(compSign string, compName string) Server {
	if s.Server(compName) != nil {
		UseExitf("conflicting server with a same component name '%s'\n", compName)
	}
	create, ok := serverCreators[compSign]
	if !ok {
		UseExitln("unknown server type: " + compSign)
	}
	server := create(compName, s)
	server.setShell(server)
	s.servers[compName] = server
	return server
}
func (s *Stage) createCronjob(compSign string, compName string) Cronjob {
	if s.Cronjob(compName) != nil {
		UseExitf("conflicting cronjob with a same component name '%s'\n", compName)
	}
	create, ok := cronjobCreators[compSign]
	if !ok {
		UseExitln("unknown cronjob type: " + compSign)
	}
	cronjob := create(compName, s)
	cronjob.setShell(cronjob)
	s.cronjobs[compName] = cronjob
	return cronjob
}

func (s *Stage) decFixture() { s.subs.Done() }
func (s *Stage) DecBackend() { s.subs.Done() }
func (s *Stage) DecRpcsvc()  { s.subs.Done() }
func (s *Stage) DecHstate()  { s.subs.Done() }
func (s *Stage) DecHcache()  { s.subs.Done() }
func (s *Stage) DecWebapp()  { s.subs.Done() }
func (s *Stage) DecRouter()  { s.subs.Done() }
func (s *Stage) DecServer()  { s.subs.Done() }
func (s *Stage) DecCronjob() { s.subs.Done() }

func (s *Stage) Clock() *clockFixture   { return s.clock }
func (s *Stage) Fcache() *fcacheFixture { return s.fcache }
func (s *Stage) Resolv() *resolvFixture { return s.resolv }

func (s *Stage) Fixture(compSign string) fixture        { return s.fixtures[compSign] }
func (s *Stage) Backend(compName string) Backend        { return s.backends[compName] }
func (s *Stage) Rpcsvc(compName string) *Rpcsvc         { return s.rpcsvcs[compName] }
func (s *Stage) Hstate(compName string) Hstate          { return s.hstates[compName] }
func (s *Stage) Hcache(compName string) Hcache          { return s.hcaches[compName] }
func (s *Stage) Webapp(compName string) *Webapp         { return s.webapps[compName] }
func (s *Stage) QUIXRouter(compName string) *QUIXRouter { return s.quixRouters[compName] }
func (s *Stage) TCPXRouter(compName string) *TCPXRouter { return s.tcpxRouters[compName] }
func (s *Stage) UDPXRouter(compName string) *UDPXRouter { return s.udpxRouters[compName] }
func (s *Stage) Server(compName string) Server          { return s.servers[compName] }
func (s *Stage) Cronjob(compName string) Cronjob        { return s.cronjobs[compName] }

func (s *Stage) Start(id int32) {
	s.id = id
	s.numCPU = runtime.NumCPU()

	if DebugLevel() >= 2 {
		Printf("size of server1Conn = %d\n", unsafe.Sizeof(server1Conn{}))
		Printf("size of backend1Conn = %d\n", unsafe.Sizeof(backend1Conn{}))
		Printf("size of server2Conn = %d\n", unsafe.Sizeof(server2Conn{}))
		Printf("size of backend2Conn = %d\n", unsafe.Sizeof(backend2Conn{}))
		Printf("size of server2Stream = %d\n", unsafe.Sizeof(server2Stream{}))
		Printf("size of backend2Stream = %d\n", unsafe.Sizeof(backend2Stream{}))
		Printf("size of server3Conn = %d\n", unsafe.Sizeof(server3Conn{}))
		Printf("size of backend3Conn = %d\n", unsafe.Sizeof(backend3Conn{}))
		Printf("size of server3Stream = %d\n", unsafe.Sizeof(server3Stream{}))
		Printf("size of backend3Stream = %d\n", unsafe.Sizeof(backend3Stream{}))
		Printf("size of http2InFrame = %d\n", unsafe.Sizeof(http2InFrame{}))
		Printf("size of http2OutFrame = %d\n", unsafe.Sizeof(http2OutFrame[*server2Stream]{}))
		Printf("size of hpackTable = %d\n", unsafe.Sizeof(hpackTable{}))
	}
	if DebugLevel() >= 1 {
		Printf("stageID=%d\n", s.id)
		Printf("numCPU=%d\n", s.numCPU)
		Printf("topDir=%s\n", TopDir())
		Printf("logDir=%s\n", LogDir())
		Printf("tmpDir=%s\n", TmpDir())
		Printf("varDir=%s\n", VarDir())
	}

	// Init the running environment
	rand.Seed(time.Now().UnixNano())
	if err := os.Chdir(TopDir()); err != nil {
		EnvExitln(err.Error())
	}

	// Configure all components in current stage
	if err := s.configure(); err != nil {
		UseExitln(err.Error())
	}

	// Bind rpcsvcs and webapps to servers
	if DebugLevel() >= 1 {
		Println("bind rpcsvcs and webapps to servers")
	}
	for _, server := range s.servers {
		if rpcServer, ok := server.(*hrpcServer); ok {
			rpcServer.bindRpcsvcs()
		} else if webServer, ok := server.(HTTPServer); ok {
			webServer.bindWebapps()
		}
	}

	// Prepare all components in current stage
	if err := s.prepare(); err != nil {
		EnvExitln(err.Error())
	}

	// Start all components in current stage
	s.startFixtures() // go fixture.run()
	s.startBackends() // go backend.Maintain()
	s.startRpcsvcs()  // go rpcsvc.maintain()
	s.startHstates()  // go hstate.Maintain()
	s.startHcaches()  // go hcache.Maintain()
	s.startWebapps()  // go webapp.maintain()
	s.startRouters()  // go router.serve()
	s.startServers()  // go server.Serve()
	s.startCronjobs() // go cronjob.Schedule()
}

func (s *Stage) configure() (err error) {
	if DebugLevel() >= 1 {
		Println("now configure stage")
	}
	defer func() {
		if x := recover(); x != nil {
			err = x.(error)
		}
	}()
	s.OnConfigure()
	if DebugLevel() >= 1 {
		Println("stage configured")
	}
	return nil
}
func (s *Stage) prepare() (err error) {
	if DebugLevel() >= 1 {
		Println("now prepare stage")
	}
	defer func() {
		if x := recover(); x != nil {
			err = x.(error)
		}
	}()
	s.OnPrepare()
	if DebugLevel() >= 1 {
		Println("stage prepared")
	}
	return nil
}

func (s *Stage) startFixtures() {
	for _, fixture := range s.fixtures {
		if DebugLevel() >= 1 {
			Printf("fixture=%s go run()\n", fixture.CompName())
		}
		go fixture.run()
	}
}
func (s *Stage) startBackends() {
	for _, backend := range s.backends {
		if DebugLevel() >= 1 {
			Printf("backend=%s go maintain()\n", backend.CompName())
		}
		go backend.Maintain()
	}
}
func (s *Stage) startRpcsvcs() {
	for _, rpcsvc := range s.rpcsvcs {
		if DebugLevel() >= 1 {
			Printf("rpcsvc=%s go maintain()\n", rpcsvc.CompName())
		}
		go rpcsvc.maintain()
	}
}
func (s *Stage) startHstates() {
	for _, hstate := range s.hstates {
		if DebugLevel() >= 1 {
			Printf("hstate=%s go Maintain()\n", hstate.CompName())
		}
		go hstate.Maintain()
	}
}
func (s *Stage) startHcaches() {
	for _, hcache := range s.hcaches {
		if DebugLevel() >= 1 {
			Printf("hcache=%s go Maintain()\n", hcache.CompName())
		}
		go hcache.Maintain()
	}
}
func (s *Stage) startWebapps() {
	for _, webapp := range s.webapps {
		if DebugLevel() >= 1 {
			Printf("webapp=%s go maintain()\n", webapp.CompName())
		}
		go webapp.maintain()
	}
}
func (s *Stage) startRouters() {
	for _, quixRouter := range s.quixRouters {
		if DebugLevel() >= 1 {
			Printf("quixRouter=%s go serve()\n", quixRouter.CompName())
		}
		go quixRouter.Serve()
	}
	for _, tcpxRouter := range s.tcpxRouters {
		if DebugLevel() >= 1 {
			Printf("tcpxRouter=%s go serve()\n", tcpxRouter.CompName())
		}
		go tcpxRouter.Serve()
	}
	for _, udpxRouter := range s.udpxRouters {
		if DebugLevel() >= 1 {
			Printf("udpxRouter=%s go serve()\n", udpxRouter.CompName())
		}
		go udpxRouter.Serve()
	}
}
func (s *Stage) startServers() {
	for _, server := range s.servers {
		if DebugLevel() >= 1 {
			Printf("server=%s go Serve()\n", server.CompName())
		}
		go server.Serve()
	}
}
func (s *Stage) startCronjobs() {
	for _, cronjob := range s.cronjobs {
		if DebugLevel() >= 1 {
			Printf("cronjob=%s go Schedule()\n", cronjob.CompName())
		}
		go cronjob.Schedule()
	}
}

func (s *Stage) ID() int32   { return s.id }
func (s *Stage) NumCPU() int { return s.numCPU }

func (s *Stage) ProfCPU() {
	file, err := os.Create(s.cpuFile)
	if err != nil {
		return
	}
	defer file.Close()
	pprof.StartCPUProfile(file)
	time.Sleep(5 * time.Second)
	pprof.StopCPUProfile()
}
func (s *Stage) ProfHeap() {
	file, err := os.Create(s.hepFile)
	if err != nil {
		return
	}
	defer file.Close()
	runtime.GC()
	time.Sleep(5 * time.Second)
	runtime.GC()
	pprof.Lookup("heap").WriteTo(file, 1)
}
func (s *Stage) ProfThread() {
	file, err := os.Create(s.thrFile)
	if err != nil {
		return
	}
	defer file.Close()
	time.Sleep(5 * time.Second)
	pprof.Lookup("threadcreate").WriteTo(file, 1)
}
func (s *Stage) ProfGoroutine() {
	file, err := os.Create(s.grtFile)
	if err != nil {
		return
	}
	defer file.Close()
	pprof.Lookup("goroutine").WriteTo(file, 2)
}
func (s *Stage) ProfBlock() {
	file, err := os.Create(s.blkFile)
	if err != nil {
		return
	}
	defer file.Close()
	runtime.SetBlockProfileRate(1)
	time.Sleep(5 * time.Second)
	pprof.Lookup("block").WriteTo(file, 1)
	runtime.SetBlockProfileRate(0)
}

func (s *Stage) Quit() {
	s.OnShutdown()
	if DebugLevel() >= 2 {
		Printf("stage id=%d: quit.\n", s.id)
	}
}

////////////////////////////////////////////////////////////////////////////////

// fixture component.
//
// Fixtures are singleton components, created by Stage, and only exist in internal.
// Some critical components, like clock and resolv, are implemented as fixtures.
//
// Fixtures are singletons in a Stage.
type fixture interface {
	// Imports
	Component
	// Methods
	run() // runner
}

// fixture_ is a parent.
type fixture_ struct { // for all fixtures
	// Parent
	Component_
	// Assocs
	stage *Stage // current stage
}

func (f *fixture_) onCreate(compName string, stage *Stage) {
	f.MakeComp(compName)
	f.stage = stage
}

const signClock = "clock"

func init() { registerFixture(signClock) }

func createClock(stage *Stage) *clockFixture {
	clock := new(clockFixture)
	clock.onCreate(stage)
	clock.setShell(clock)
	return clock
}

// clockFixture
type clockFixture struct {
	// Parent
	fixture_
	// States
	resolution time.Duration
	date       atomic.Int64 // 4, 4+4 4 4+4+4+4 4+4:4+4:4+4 = 56bit
}

func (f *clockFixture) onCreate(stage *Stage) {
	f.fixture_.onCreate(signClock, stage)
	f.resolution = 100 * time.Millisecond
	f.date.Store(0x7394804991b60000) // Sun, 06 Nov 1994 08:49:37
}
func (f *clockFixture) OnShutdown() { close(f.ShutChan) } // notifies run()

func (f *clockFixture) OnConfigure() {
}
func (f *clockFixture) OnPrepare() {
}

func (f *clockFixture) run() { // runner
	f.LoopRun(f.resolution, func(now time.Time) {
		now = now.UTC()
		weekday := now.Weekday()       // weekday: 0-6
		year, month, day := now.Date() // month: 1-12
		hour, minute, second := now.Clock()
		date := int64(0)
		date |= int64(second%10) << 60
		date |= int64(second/10) << 56
		date |= int64(minute%10) << 52
		date |= int64(minute/10) << 48
		date |= int64(hour%10) << 44
		date |= int64(hour/10) << 40
		date |= int64(year%10) << 36
		date |= int64(year/10%10) << 32
		date |= int64(year/100%10) << 28
		date |= int64(year/1000) << 24
		date |= int64(month) << 20
		date |= int64(day%10) << 16
		date |= int64(day/10) << 12
		date |= int64(weekday) << 8
		f.date.Store(date)
	})
	if DebugLevel() >= 2 {
		Println("clock done")
	}
	f.stage.decFixture()
}

func (f *clockFixture) writeDate1(dst []byte) int {
	i := copy(dst, "date: ")
	i += f.writeDate(dst[i:])
	dst[i] = '\r'
	dst[i+1] = '\n'
	return i + 2
}
func (f *clockFixture) writeDate(dst []byte) int {
	date := f.date.Load()
	s := clockDayString[3*(date>>8&0xf):]
	dst[0] = s[0] // 'S'
	dst[1] = s[1] // 'u'
	dst[2] = s[2] // 'n'
	dst[3] = ','
	dst[4] = ' '
	dst[5] = byte(date>>12&0xf) + '0' // '0'
	dst[6] = byte(date>>16&0xf) + '0' // '6'
	dst[7] = ' '
	s = clockMonthString[3*(date>>20&0xf-1):]
	dst[8] = s[0]  // 'N'
	dst[9] = s[1]  // 'o'
	dst[10] = s[2] // 'v'
	dst[11] = ' '
	dst[12] = byte(date>>24&0xf) + '0' // '1'
	dst[13] = byte(date>>28&0xf) + '0' // '9'
	dst[14] = byte(date>>32&0xf) + '0' // '9'
	dst[15] = byte(date>>36&0xf) + '0' // '4'
	dst[16] = ' '
	dst[17] = byte(date>>40&0xf) + '0' // '0'
	dst[18] = byte(date>>44&0xf) + '0' // '8'
	dst[19] = ':'
	dst[20] = byte(date>>48&0xf) + '0' // '4'
	dst[21] = byte(date>>52&0xf) + '0' // '9'
	dst[22] = ':'
	dst[23] = byte(date>>56&0xf) + '0' // '3'
	dst[24] = byte(date>>60&0xf) + '0' // '7'
	dst[25] = ' '
	dst[26] = 'G'
	dst[27] = 'M'
	dst[28] = 'T'
	return clockHTTPDateSize
}

func clockWriteHTTPDate1(dst []byte, fieldName []byte, unixTime int64) int {
	i := copy(dst, fieldName)
	dst[i] = ':'
	dst[i+1] = ' '
	i += 2
	date := time.Unix(unixTime, 0)
	date = date.UTC()
	i += clockWriteHTTPDate(dst[i:], date)
	dst[i] = '\r'
	dst[i+1] = '\n'
	return i + 2
}
func clockWriteHTTPDate(dst []byte, date time.Time) int {
	if len(dst) < clockHTTPDateSize {
		BugExitln("invalid buffer for clockWriteHTTPDate")
	}
	s := clockDayString[3*date.Weekday():]
	dst[0] = s[0] // 'S'
	dst[1] = s[1] // 'u'
	dst[2] = s[2] // 'n'
	dst[3] = ','
	dst[4] = ' '
	year, month, day := date.Date() // month: 1-12
	dst[5] = byte(day/10) + '0'     // '0'
	dst[6] = byte(day%10) + '0'     // '6'
	dst[7] = ' '
	s = clockMonthString[3*(month-1):]
	dst[8] = s[0]  // 'N'
	dst[9] = s[1]  // 'o'
	dst[10] = s[2] // 'v'
	dst[11] = ' '
	dst[12] = byte(year/1000) + '0'   // '1'
	dst[13] = byte(year/100%10) + '0' // '9'
	dst[14] = byte(year/10%10) + '0'  // '9'
	dst[15] = byte(year%10) + '0'     // '4'
	dst[16] = ' '
	hour, minute, second := date.Clock()
	dst[17] = byte(hour/10) + '0' // '0'
	dst[18] = byte(hour%10) + '0' // '8'
	dst[19] = ':'
	dst[20] = byte(minute/10) + '0' // '4'
	dst[21] = byte(minute%10) + '0' // '9'
	dst[22] = ':'
	dst[23] = byte(second/10) + '0' // '3'
	dst[24] = byte(second%10) + '0' // '7'
	dst[25] = ' '
	dst[26] = 'G'
	dst[27] = 'M'
	dst[28] = 'T'
	return clockHTTPDateSize
}

func clockParseHTTPDate(date []byte) (int64, bool) {
	// format 0: Sun, 06 Nov 1994 08:49:37 GMT
	// format 1: Sunday, 06-Nov-94 08:49:37 GMT
	// format 2: Sun Nov  6 08:49:37 1994
	var format int
	fore, edge := 0, len(date)
	if n := len(date); n == clockHTTPDateSize {
		format = 0
		fore = 5 // skip 'Sun, ', stops at '0'
	} else if n >= 30 && n <= 33 {
		format = 1
		for fore < edge && date[fore] != ' ' { // skip 'Sunday, ', stops at '0'
			fore++
		}
		if edge-fore != 23 {
			return 0, false
		}
		fore++
	} else if n == clockASCTimeSize {
		format = 2
		fore = 4 // skip 'Sun ', stops at 'N'
	} else {
		return 0, false
	}
	var year, month, day, hour, minute, second int
	var b, b0, b1, b2, b3 byte
	if format != 2 {
		if b0, b1 = date[fore], date[fore+1]; b0 >= '0' && b0 <= '9' && b1 >= '0' && b1 <= '9' {
			day = int(b0-'0')*10 + int(b1-'0')
		} else {
			return 0, false
		}
		fore += 3
		if b = date[fore-1]; (format == 0 && b != ' ') || (format == 1 && b != '-') {
			return 0, false
		}
	}
	hash := uint16(date[fore]) + uint16(date[fore+1]) + uint16(date[fore+2])
	m := clockMonthTable[clockMonthFind(hash)]
	if m.hash == hash && string(date[fore:fore+3]) == clockMonthString[m.from:m.edge] {
		month = int(m.month)
	} else {
		return 0, false
	}
	fore += 4
	if b = date[fore-1]; (format == 1 && b != '-') || (format != 1 && b != ' ') {
		return 0, false
	}
	if format == 0 {
		b0, b1, b2, b3 = date[fore], date[fore+1], date[fore+2], date[fore+3]
		if b0 >= '0' && b0 <= '9' && b1 >= '0' && b1 <= '9' && b2 >= '0' && b2 <= '9' && b3 >= '0' && b3 <= '9' {
			year = int(b0-'0')*1000 + int(b1-'0')*100 + int(b2-'0')*10 + int(b3-'0')
			fore += 5
		} else {
			return 0, false
		}
	} else if format == 1 {
		b0, b1 = date[fore], date[fore+1]
		if b0 >= '0' && b0 <= '9' && b1 >= '0' && b1 <= '9' {
			year = int(b0-'0')*10 + int(b1-'0')
			if year < 70 {
				year += 2000
			} else {
				year += 1900
			}
			fore += 3
		} else {
			return 0, false
		}
	} else {
		b0, b1 = date[fore], date[fore+1]
		if b0 == ' ' {
			b0 = '0'
		}
		if b0 >= '0' && b0 <= '9' && b1 >= '0' && b1 <= '9' {
			day = int(b0-'0')*10 + int(b1-'0')
		} else {
			return 0, false
		}
		fore += 3
	}
	b0, b1 = date[fore], date[fore+1]
	if b0 >= '0' && b0 <= '9' && b1 >= '0' && b1 <= '9' {
		hour = int(b0-'0')*10 + int(b1-'0')
		fore += 3
	} else {
		return 0, false
	}
	b0, b1 = date[fore], date[fore+1]
	if b0 >= '0' && b0 <= '9' && b1 >= '0' && b1 <= '9' {
		minute = int(b0-'0')*10 + int(b1-'0')
		fore += 3
	} else {
		return 0, false
	}
	b0, b1 = date[fore], date[fore+1]
	if b0 >= '0' && b0 <= '9' && b1 >= '0' && b1 <= '9' {
		second = int(b0-'0')*10 + int(b1-'0')
		fore += 3
	} else {
		return 0, false
	}
	if date[fore-1] != ' ' || date[fore-4] != ':' || date[fore-7] != ':' || date[fore-10] != ' ' || hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}
	if format == 2 {
		b0, b1, b2, b3 = date[fore], date[fore+1], date[fore+2], date[fore+3]
		if b0 >= '0' && b0 <= '9' && b1 >= '0' && b1 <= '9' && b2 >= '0' && b2 <= '9' && b3 >= '0' && b3 <= '9' {
			year = int(b0-'0')*1000 + int(b1-'0')*100 + int(b2-'0')*10 + int(b3-'0')
		} else {
			return 0, false
		}
	} else if date[fore] != 'G' || date[fore+1] != 'M' || date[fore+2] != 'T' {
		return 0, false
	}
	leap := year%4 == 0 && (year%100 != 0 || year%400 == 0)
	if day == 29 && month == 2 {
		if !leap {
			return 0, false
		}
	} else if day > int(m.days) {
		return 0, false
	}
	days := int(m.past)
	if year > 0 {
		year--
		days += (year/4 - year/100 + year/400 + 1) // year 0000 is a leap year
		days += (year + 1) * 365
	}
	if leap && month > 2 {
		days++
	}
	days += (day - 1) // today has not past
	days -= 719528    // total days between [0000-01-01 00:00:00, 1970-01-01 00:00:00)
	return int64(days)*86400 + int64(hour*3600+minute*60+second), true
}

const ( // clock related
	clockHTTPDateSize = len("Sun, 06 Nov 1994 08:49:37 GMT")
	clockASCTimeSize  = len("Sun Nov  6 08:49:37 1994")
	clockDayString    = "SunMonTueWedThuFriSat"
	clockMonthString  = "JanFebMarAprMayJunJulAugSepOctNovDec"
)

var ( // minimal perfect hash table for months
	clockMonthTable = [12]struct {
		hash  uint16
		from  int8
		edge  int8
		month int8
		days  int8
		past  int16
	}{
		0:  {285, 21, 24, 8, 31, 212},  // Aug
		1:  {296, 24, 27, 9, 30, 243},  // Sep
		2:  {268, 33, 36, 12, 31, 334}, // Dec
		3:  {288, 6, 9, 3, 31, 59},     // Mar
		4:  {301, 15, 18, 6, 30, 151},  // Jun
		5:  {295, 12, 15, 5, 31, 120},  // May
		6:  {307, 30, 33, 11, 30, 304}, // Nov
		7:  {299, 18, 21, 7, 31, 181},  // Jul
		8:  {294, 27, 30, 10, 31, 273}, // Oct
		9:  {291, 9, 12, 4, 30, 90},    // Apr
		10: {269, 3, 6, 2, 28, 31},     // Feb
		11: {281, 0, 3, 1, 31, 0},      // Jan
	}
	clockMonthFind = func(hash uint16) int { return (5509728 / int(hash)) % len(clockMonthTable) }
)

const signFcache = "fcache"

func init() { registerFixture(signFcache) }

func createFcache(stage *Stage) *fcacheFixture {
	fcache := new(fcacheFixture)
	fcache.onCreate(stage)
	fcache.setShell(fcache)
	return fcache
}

// fcacheFixture caches file descriptors and contents.
type fcacheFixture struct {
	// Parent
	fixture_
	// States
	smallFileSize int64 // what size is considered as small file
	maxSmallFiles int32 // max number of small files. for small files, contents are cached
	maxLargeFiles int32 // max number of large files. for large files, *os.File are cached
	cacheTimeout  time.Duration
	rwMutex       sync.RWMutex // protects entries below
	entries       map[string]*fcacheEntry
}

func (f *fcacheFixture) onCreate(stage *Stage) {
	f.fixture_.onCreate(signFcache, stage)
	f.entries = make(map[string]*fcacheEntry)
}
func (f *fcacheFixture) OnShutdown() { close(f.ShutChan) } // notifies run()

func (f *fcacheFixture) OnConfigure() {
	// .smallFileSize
	f.ConfigureInt64("smallFileSize", &f.smallFileSize, func(value int64) error {
		if value > 0 {
			return nil
		}
		return errors.New(".smallFileSize has an invalid value")
	}, _64K1)

	// .maxSmallFiles
	f.ConfigureInt32("maxSmallFiles", &f.maxSmallFiles, func(value int32) error {
		if value > 0 {
			return nil
		}
		return errors.New(".maxSmallFiles has an invalid value")
	}, 1000)

	// .maxLargeFiles
	f.ConfigureInt32("maxLargeFiles", &f.maxLargeFiles, func(value int32) error {
		if value > 0 {
			return nil
		}
		return errors.New(".maxLargeFiles has an invalid value")
	}, 500)

	// .cacheTimeout
	f.ConfigureDuration("cacheTimeout", &f.cacheTimeout, func(value time.Duration) error {
		if value > 0 {
			return nil
		}
		return errors.New(".cacheTimeout has an invalid value")
	}, 1*time.Second)
}
func (f *fcacheFixture) OnPrepare() {
}

func (f *fcacheFixture) run() { // runner
	f.LoopRun(time.Second, func(now time.Time) {
		f.rwMutex.Lock()
		for path, entry := range f.entries {
			if entry.last.After(now) {
				continue
			}
			if entry.isLarge() {
				entry.decRef()
			}
			delete(f.entries, path)
			if DebugLevel() >= 2 {
				Printf("fcache entry deleted: %s\n", path)
			}
		}
		f.rwMutex.Unlock()
	})
	f.rwMutex.Lock()
	f.entries = nil
	f.rwMutex.Unlock()

	if DebugLevel() >= 2 {
		Println("fcache done")
	}
	f.stage.decFixture()
}

func (f *fcacheFixture) getEntry(path []byte) (*fcacheEntry, error) {
	f.rwMutex.RLock()
	defer f.rwMutex.RUnlock()

	if entry, ok := f.entries[WeakString(path)]; ok {
		if entry.isLarge() {
			entry.addRef()
		}
		return entry, nil
	} else {
		return nil, fcacheNotExist
	}
}

var fcacheNotExist = errors.New("entry not exist")

func (f *fcacheFixture) newEntry(path string) (*fcacheEntry, error) {
	f.rwMutex.RLock()
	if entry, ok := f.entries[path]; ok {
		if entry.isLarge() {
			entry.addRef()
		}

		f.rwMutex.RUnlock()
		return entry, nil
	}
	f.rwMutex.RUnlock()

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}

	entry := new(fcacheEntry)
	if info.IsDir() {
		entry.kind = fcacheKindDir
		file.Close()
	} else if fileSize := info.Size(); fileSize <= f.smallFileSize {
		text := make([]byte, fileSize)
		if _, err := io.ReadFull(file, text); err != nil {
			file.Close()
			return nil, err
		}
		entry.kind = fcacheKindSmall
		entry.info = info
		entry.text = text
		file.Close()
	} else { // large file
		entry.kind = fcacheKindLarge
		entry.file = file
		entry.info = info
		entry.nRef.Store(1) // current caller
	}
	entry.last = time.Now().Add(f.cacheTimeout)

	f.rwMutex.Lock()
	f.entries[path] = entry
	f.rwMutex.Unlock()

	return entry, nil
}

// fcacheEntry
type fcacheEntry struct {
	kind int8         // see fcacheKindXXX
	file *os.File     // only for large file
	info os.FileInfo  // only for files, not directories
	text []byte       // content of small file
	last time.Time    // expire time
	nRef atomic.Int64 // only for large file
}

const ( // fcache entry kinds
	fcacheKindDir = iota
	fcacheKindSmall
	fcacheKindLarge
)

func (e *fcacheEntry) isDir() bool   { return e.kind == fcacheKindDir }
func (e *fcacheEntry) isLarge() bool { return e.kind == fcacheKindLarge }
func (e *fcacheEntry) isSmall() bool { return e.kind == fcacheKindSmall }

func (e *fcacheEntry) addRef() {
	e.nRef.Add(1)
}
func (e *fcacheEntry) decRef() {
	if e.nRef.Add(-1) < 0 {
		if DebugLevel() >= 2 {
			Printf("fcache large entry closed: %s\n", e.file.Name())
		}
		e.file.Close()
	}
}

const signResolv = "resolv"

func init() { registerFixture(signResolv) }

func createResolv(stage *Stage) *resolvFixture {
	resolv := new(resolvFixture)
	resolv.onCreate(stage)
	resolv.setShell(resolv)
	return resolv
}

// resolvFixture resolves names.
type resolvFixture struct {
	// Parent
	fixture_
	// States
}

func (f *resolvFixture) onCreate(stage *Stage) {
	f.fixture_.onCreate(signResolv, stage)
}
func (f *resolvFixture) OnShutdown() { close(f.ShutChan) } // notifies run()

func (f *resolvFixture) OnConfigure() {
}
func (f *resolvFixture) OnPrepare() {
}

func (f *resolvFixture) run() { // runner
	f.LoopRun(time.Second, func(now time.Time) {
		// TODO
	})
	if DebugLevel() >= 2 {
		Println("resolv done")
	}
	f.stage.decFixture()
}

func (f *resolvFixture) Register(name string, addresses []string) bool {
	// TODO
	return false
}

func (f *resolvFixture) Resolve(name string) (address string) {
	// TODO
	return ""
}

////////////////////////////////////////////////////////////////////////////////

// Cronjob component.
//
// Cronjobs are background tasks that are scheduled to run periodically.
type Cronjob interface {
	// Imports
	Component
	// Methods
	Schedule() // runner
}

// Cronjob_ is a parent.
type Cronjob_ struct { // for all cronjobs
	// Parent
	Component_
	// Assocs
	stage *Stage // current stage
	// States
}

func (j *Cronjob_) OnCreate(compName string, stage *Stage) {
	j.MakeComp(compName)
	j.stage = stage
}

func (j *Cronjob_) Stage() *Stage { return j.stage }

func init() {
	RegisterCronjob("statCronjob", func(compName string, stage *Stage) Cronjob {
		j := new(statCronjob)
		j.onCreate(compName, stage)
		return j
	})
}

// statCronjob reports statistics about current stage.
type statCronjob struct {
	// Parent
	Cronjob_
	// States
}

func (j *statCronjob) onCreate(compName string, stage *Stage) {
	j.Cronjob_.OnCreate(compName, stage)
}
func (j *statCronjob) OnShutdown() { close(j.ShutChan) } // notifies Schedule()

func (j *statCronjob) OnConfigure() {
	// TODO
}
func (j *statCronjob) OnPrepare() {
	// TODO
}

func (j *statCronjob) Schedule() { // runner
	j.LoopRun(time.Minute, func(now time.Time) {
		// TODO
	})
	if DebugLevel() >= 2 {
		Printf("statCronjob=%s done\n", j.CompName())
	}
	j.stage.DecCronjob()
}

func init() {
	RegisterCronjob("demoCronjob", func(compName string, stage *Stage) Cronjob {
		j := new(demoCronjob)
		j.onCreate(compName, stage)
		return j
	})
}

// demoCronjob
type demoCronjob struct {
	// Parent
	Cronjob_
	// States
}

func (j *demoCronjob) onCreate(compName string, stage *Stage) {
	j.Cronjob_.OnCreate(compName, stage)
}
func (j *demoCronjob) OnShutdown() { close(j.ShutChan) } // notifies Schedule()

func (j *demoCronjob) OnConfigure() {}
func (j *demoCronjob) OnPrepare()   {}

func (j *demoCronjob) Schedule() { // runner
	j.LoopRun(time.Minute, func(now time.Time) {
		// TODO
	})
	if DebugLevel() >= 2 {
		Printf("demoCronjob=%s done\n", j.CompName())
	}
	j.stage.DecCronjob()
}
