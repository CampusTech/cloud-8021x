// Package migrations embeds the reviewed PostgreSQL application schema.
package migrations

import _ "embed"

//go:embed 001_ledger.sql
var Ledger string

//go:embed 002_collection.sql
var Collection string

//go:embed 003_termination_cause.sql
var TerminationCause string

//go:embed 004_reserved.sql
var ReservedV4 string

const Version = 4
