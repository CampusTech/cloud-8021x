package config

import "errors"

type RuntimePool string

const (
	PoolAccounting   RuntimePool = "accounting"
	PoolExport       RuntimePool = "export"
	PoolAuth         RuntimePool = "auth"
	PoolCertificates RuntimePool = "certificates"
	PoolObservation  RuntimePool = "observation"
)

// RuntimePoolLimit partitions one physical node's total runtime role budget.
// Unused certificate capacity is reserved, never borrowed by busy workers.
func (c Database) RuntimePoolLimit(pool RuntimePool) (int, error) {
	if c.MaxConnections < 8 || c.MaxConnections > 64 || c.MinConnections != 0 {
		return 0, errors.New("aggregate runtime database budget must be 8..64 with zero warm minimum")
	}
	switch pool {
	case PoolAccounting:
		return (c.MaxConnections - 4) / 2, nil
	case PoolExport:
		return c.MaxConnections - 4 - (c.MaxConnections-4)/2, nil
	case PoolAuth, PoolObservation:
		return 1, nil
	case PoolCertificates:
		return 2, nil
	default:
		return 0, errors.New("unknown runtime database pool")
	}
}
