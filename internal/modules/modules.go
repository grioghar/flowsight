// Package modules links every built-in module into the binary. A module
// registers itself from its own init(); importing it here is all it takes.
package modules

import (
	_ "github.com/grioghar/flowsight/internal/modules/appcontrol"
	_ "github.com/grioghar/flowsight/internal/modules/categories"
	_ "github.com/grioghar/flowsight/internal/modules/dns"
	_ "github.com/grioghar/flowsight/internal/modules/firewall"
	_ "github.com/grioghar/flowsight/internal/modules/identity"
	_ "github.com/grioghar/flowsight/internal/modules/ids"
	_ "github.com/grioghar/flowsight/internal/modules/policy"
	_ "github.com/grioghar/flowsight/internal/modules/tls"
	_ "github.com/grioghar/flowsight/internal/modules/visibility"
	_ "github.com/grioghar/flowsight/internal/modules/web"
)
