// Package module defines the interfaces between the OSS engine and paid
// modules. Paid implementations live in github.com/sd-strax/reckon-enterprise
// and never run inside the OSS binary — the OSS-default stubs in this
// package (DisabledTenancy, DisabledGovernance) are always used in OSS
// builds.
//
// See design/05-component-architecture.md §13 for the architectural
// commitments this package implements, and implementation/module-layout.md
// for the two-repo boundary.
package module
