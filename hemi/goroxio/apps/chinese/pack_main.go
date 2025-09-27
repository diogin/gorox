// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

package chinese

import (
	"github.com/diogin/gorox/hemi/builtin/handlets/sitex"

	. "github.com/diogin/gorox/hemi"
)

type Pack struct {
	sitex.Pack_
}

func (p *Pack) OPTIONS_index(req ServerRequest, resp ServerResponse) {
	if req.IsAsteriskOptions() {
		resp.Send("this is OPTIONS *")
	} else {
		resp.Send("this is OPTIONS / or OPTIONS /index")
	}
}
