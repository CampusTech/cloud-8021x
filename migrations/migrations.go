// Package migrations embeds the reviewed PostgreSQL application schema.
package migrations

import _ "embed"

//go:embed 001_ledger.sql
var Ledger string

//go:embed 002_collection.sql
var Collection string

const Version = 2
