// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

package hemiapp

import (
	. "github.com/diogin/gorox/hemi"
)

func (h *hemiappHandlet) GET_querystring(req ServerRequest, resp ServerResponse) {
	resp.Send(req.QueryString())
}
