// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// Builtin components are the standard components that supplement the core components of the Hemi Engine.

package builtin

import (
	_ "github.com/diogin/gorox/hemi/builtin/backends/mysql"
	_ "github.com/diogin/gorox/hemi/builtin/backends/pgsql"
	_ "github.com/diogin/gorox/hemi/builtin/backends/redis"
	_ "github.com/diogin/gorox/hemi/builtin/cronjobs/clean"
	_ "github.com/diogin/gorox/hemi/builtin/dealets/tcpx/access"
	_ "github.com/diogin/gorox/hemi/builtin/dealets/tcpx/limit"
	_ "github.com/diogin/gorox/hemi/builtin/dealets/tcpx/mysql"
	_ "github.com/diogin/gorox/hemi/builtin/dealets/tcpx/pgsql"
	_ "github.com/diogin/gorox/hemi/builtin/dealets/tcpx/redis"
	_ "github.com/diogin/gorox/hemi/builtin/dealets/udpx/dns"
	_ "github.com/diogin/gorox/hemi/builtin/handlets/cgi"
	_ "github.com/diogin/gorox/hemi/builtin/handlets/favicon"
	_ "github.com/diogin/gorox/hemi/builtin/handlets/hostname"
	_ "github.com/diogin/gorox/hemi/builtin/handlets/https"
	_ "github.com/diogin/gorox/hemi/builtin/handlets/limit"
	_ "github.com/diogin/gorox/hemi/builtin/handlets/mp4"
	_ "github.com/diogin/gorox/hemi/builtin/handlets/rewriter"
	_ "github.com/diogin/gorox/hemi/builtin/handlets/sitex"
	_ "github.com/diogin/gorox/hemi/builtin/handlets/webdav"
	_ "github.com/diogin/gorox/hemi/builtin/hcaches/filesys"
	_ "github.com/diogin/gorox/hemi/builtin/hcaches/memory"
	_ "github.com/diogin/gorox/hemi/builtin/hstates/filesys"
	_ "github.com/diogin/gorox/hemi/builtin/hstates/redis"
	_ "github.com/diogin/gorox/hemi/builtin/loggers/simple"
	_ "github.com/diogin/gorox/hemi/builtin/mappers/simple"
	_ "github.com/diogin/gorox/hemi/builtin/revisers/gunzip"
	_ "github.com/diogin/gorox/hemi/builtin/revisers/gzip"
	_ "github.com/diogin/gorox/hemi/builtin/revisers/head"
	_ "github.com/diogin/gorox/hemi/builtin/revisers/replace"
	_ "github.com/diogin/gorox/hemi/builtin/revisers/ssi"
	_ "github.com/diogin/gorox/hemi/builtin/revisers/wrap"
	_ "github.com/diogin/gorox/hemi/builtin/servers/echo"
	_ "github.com/diogin/gorox/hemi/builtin/servers/socks"
	_ "github.com/diogin/gorox/hemi/builtin/servers/tunnel"
	_ "github.com/diogin/gorox/hemi/builtin/socklets/hello"
)
