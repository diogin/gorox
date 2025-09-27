package hello

import (
	. "github.com/diogin/gorox/hemi"
)

func init() {
	RegisterServiceInit("hello", func(service *Service) error {
		return nil
	})
}
