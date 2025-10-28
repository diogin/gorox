package hello

import (
	. "github.com/diogin/gorox/hemi"
)

func init() {
	RegisterRpcsvcInit("hello", func(rpcsvc *Rpcsvc) error {
		return nil
	})
}
