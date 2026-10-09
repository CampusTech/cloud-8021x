package config

import (
	"strings"
	"testing"
)

func TestRuntimeDatabaseBudgetRequiresAllIsolatedPools(t *testing.T) {
	for _, bounds := range []string{"max_connections: 7", "min_connections: 1"} {
		if _, err := Decode(strings.NewReader(strings.Replace(validYAML, "database:", "database:\n  "+bounds, 1))); err == nil {
			t.Fatalf("accepted insufficient aggregate runtime allocation: %s", bounds)
		}
	}
}

func TestRuntimePoolPartitionPreservesReservedCapacity(t *testing.T) {
	for budget := 8; budget <= 64; budget++ {
		c := Defaults().Database
		c.MaxConnections = budget
		total := 0
		for _, pool := range []RuntimePool{PoolAccounting, PoolExport, PoolAuth, PoolCertificates, PoolObservation} {
			n, err := c.RuntimePoolLimit(pool)
			if err != nil || n < 1 {
				t.Fatal(pool, n, err)
			}
			total += n
		}
		if total != budget {
			t.Fatalf("allocation %d exceeds or strands budget %d", total, budget)
		}
		for pool, want := range map[RuntimePool]int{PoolAuth: 1, PoolCertificates: 2, PoolObservation: 1} {
			if n, _ := c.RuntimePoolLimit(pool); n != want {
				t.Fatal("reserved capacity changed", pool, n)
			}
		}
	}
}
