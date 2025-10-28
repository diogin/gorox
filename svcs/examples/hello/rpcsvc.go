package hello

import (
	. "github.com/diogin/gorox/hemi"
)

func init() {
	RegisterRpcsvcInit("hello", func(rpcsvc *Rpcsvc) error {
		rpcsvc.RegisterBundlet("hello", new(helloBundlet))
		rpcsvc.RegisterBundlet("greet", new(greetBundlet))
		return nil
	})
}

type helloBundlet struct {
	// Parent
	Bundlet_
	// States
}

type greetBundlet struct {
	// Parent
	Bundlet_
	// States
}
