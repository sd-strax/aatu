// Package config holds the deployment configuration schema and loader.
// Both OSS and paid binaries read the same schema; the OSS binary recognizes
// paid.* keys but logs a warning if they're set (no paid module to wire).
//
// See implementation/module-layout.md "Config schema sketch" for the canonical
// YAML shape.
package config
