// fastenv is a CLI tool that provides OCI-native copy-on-write workspace forking
// for AI agent orchestration. It creates isolated writable snapshot layers on top
// of a shared immutable base image using containerd's snapshot API and executes
// commands inside those forks via an OCI-compliant container runtime (crun).
//
// Canonical docs:
//   - docs/prd.md
//   - docs/architecture.md
//   - docs/implementation-plan.md (Phase 1 — Foundation)
package main

import (
	"github.com/superfield-ai/fastenv/cmd"
)

func main() {
	cmd.Execute()
}
