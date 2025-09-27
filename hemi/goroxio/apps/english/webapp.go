// Copyright (c) 2020-2025 Zhang Jingcheng <diogin@gmail.com>.
// All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

// The official website in English.

package english

import (
	"errors"

	. "github.com/diogin/gorox/hemi"
	. "github.com/diogin/gorox/hemi/builtin/handlets/sitex"
)

func init() {
	RegisterWebappInit("english", func(webapp *Webapp) error {
		logic := webapp.Handlet("logic")
		if logic == nil {
			return errors.New("no handlet named 'logic' in webapp config file")
		}
		sitex, ok := logic.(*Sitex) // must be Sitex handlet.
		if !ok {
			return errors.New("handlet in 'logic' rule is not Sitex handlet")
		}
		sitex.RegisterSite("front", Pack{})
		return nil
	})
}
