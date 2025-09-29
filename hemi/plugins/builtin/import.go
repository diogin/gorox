// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// Builtin components are the standard components that supplement the core components of the Hemi Engine.

package builtin

import (
	_ "github.com/diogin/gorox/hemi/plugins/builtin/backends/mysql"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/backends/pgsql"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/backends/redis"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/cronjobs/clean"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/dealets/tcpx/access"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/dealets/tcpx/limit"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/dealets/tcpx/mysql"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/dealets/tcpx/pgsql"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/dealets/tcpx/redis"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/dealets/udpx/dns"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/handlets/cgi"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/handlets/favicon"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/handlets/hostname"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/handlets/https"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/handlets/limit"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/handlets/mp4"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/handlets/rewriter"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/handlets/sitex"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/handlets/webdav"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/hcaches/filesys"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/hcaches/memory"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/hstates/filesys"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/hstates/redis"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/loggers/simple"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/mappers/simple"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/revisers/gunzip"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/revisers/gzip"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/revisers/head"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/revisers/replace"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/revisers/ssi"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/revisers/wrap"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/servers/echo"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/servers/socks"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/servers/tunnel"
	_ "github.com/diogin/gorox/hemi/plugins/builtin/socklets/hello"
)
