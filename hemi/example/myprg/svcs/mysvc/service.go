package mysvc

import (
	. "github.com/diogin/gorox/hemi"
)

func init() {
	RegisterServiceInit("mysvc", func(service *Service) error {
		return nil
	})
}
