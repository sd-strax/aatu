// Command aatu-backend is the OSS backend entry point.
//
// Its main package is intentionally tiny: it injects an OSS module
// builder (always-disabled stubs) into runtime.Run and lets shared OSS
// code do the rest. The paid binary's aatu-backend mirrors this shape
// with its own builder that activates paid modules when configured.
package main

import (
	"log"

	"github.com/sd-strax/aatu/module"
	"github.com/sd-strax/aatu/runtime"
)

func main() {
	err := runtime.Run(func(runtime.Config) module.Registry {
		return module.Registry{
			Tenancy:    module.DisabledTenancy{},
			Governance: module.DisabledGovernance{},
		}
	})
	if err != nil {
		log.Fatalf("runtime: %v", err)
	}
}
