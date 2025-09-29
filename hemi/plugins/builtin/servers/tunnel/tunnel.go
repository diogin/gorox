// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// HTTP tunnel proxy server.

package tunnel

import (
	"net"

	. "github.com/diogin/gorox/hemi"
)

// tunnelServer
type tunnelServer struct {
	// Parent
	Server_[*tunnelGate]
	// Assocs
	// States
}

func (s *tunnelServer) Serve() { // runner
}

// tunnelGate
type tunnelGate struct {
	// Parent
	Gate_[*tunnelServer]
	// States
	listener *net.TCPListener
}

func (g *tunnelGate) Open() error {
	return nil
}
func (g *tunnelGate) Shut() error {
	return nil
}

func (g *tunnelGate) Serve() { // runner
}

// tunnelConn
type tunnelConn struct {
}
