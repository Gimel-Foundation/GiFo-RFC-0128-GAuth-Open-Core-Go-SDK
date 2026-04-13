// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package poa

import "fmt"

func VerbURN(domain, category, action string) string {
	return fmt.Sprintf("urn:gauth:verb:%s:%s:%s", domain, category, action)
}

func PlatformURN(domain, permission string) string {
	return fmt.Sprintf("urn:gauth:platform:%s:%s", domain, permission)
}

var CoreVerbsFoundry = map[string]string{
	"foundry.file.create":     VerbURN("foundry", "file", "create"),
	"foundry.file.modify":     VerbURN("foundry", "file", "modify"),
	"foundry.file.delete":     VerbURN("foundry", "file", "delete"),
	"foundry.dependency.add":  VerbURN("foundry", "dependency", "add"),
	"foundry.command.run":     VerbURN("foundry", "command", "run"),
	"foundry.agent.delegate":  VerbURN("foundry", "agent", "delegate"),
}
