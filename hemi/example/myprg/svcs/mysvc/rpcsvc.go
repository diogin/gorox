package mysvc

import (
	. "github.com/diogin/gorox/hemi"
)

func init() {
	RegisterRpcsvcInit("mysvc", func(rpcsvc *Rpcsvc) error {
		return nil
	})
}
