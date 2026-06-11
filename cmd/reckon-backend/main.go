// Command reckon-backend is the OSS backend entry point.
//
// Its main package is intentionally tiny: it injects an OSS module builder
// (always-disabled stubs) into the shared runtime and lets runtime do the rest
// — config load, supervisor, server, lifecycle. With no arguments it boots the
// stack (runtime.Run); `reckon-backend check` validates config + module
// activation without starting services (runtime.Preflight). The paid binary's
// backend mirrors this shape with its own builder.
package main

import (
	"log"
	"os"

	"github.com/sd-strax/reckon/module"
	"github.com/sd-strax/reckon/runtime"
)

func ossModuleBuilder(runtime.Config) module.Registry {
	return module.Registry{
		Tenancy:    module.DisabledTenancy{},
		Governance: module.DisabledGovernance{},
	}
}

func main() {
	run := runtime.Run
	if len(os.Args) > 1 && os.Args[1] == "check" {
		run = runtime.Preflight
	}
	if err := run(ossModuleBuilder); err != nil {
		log.Fatalf("runtime: %v", err)
	}
}
