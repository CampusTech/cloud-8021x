// Package provisioning is used only by the private administrator runner. It is
// not imported by the daemon and never receives VM metadata credentials.
package provisioning

import (
	"errors"
	"slices"
	"strings"
)

type Grant struct {
	Grantor   string `json:"grantor"`
	Role      string `json:"role"`
	Privilege string `json:"privilege"`
	Grantable bool   `json:"grantable"`
}
type DatabaseACL struct {
	Owner  string  `json:"owner"`
	Grants []Grant `json:"grants"`
}
type Access struct {
	Role      string `json:"role"`
	Connect   bool   `json:"connect"`
	Temporary bool   `json:"temporary"`
}

func normalizeACL(a DatabaseACL) DatabaseACL {
	a.Grants = slices.Clone(a.Grants)
	slices.SortFunc(a.Grants, func(x, y Grant) int {
		for _, p := range [][2]string{{x.Grantor, y.Grantor}, {x.Role, y.Role}, {x.Privilege, y.Privilege}} {
			if n := strings.Compare(p[0], p[1]); n != 0 {
				return n
			}
		}
		if x.Grantable == y.Grantable {
			return 0
		}
		if x.Grantable {
			return 1
		}
		return -1
	})
	return a
}
func hardenedACL(original DatabaseACL, approved []Access, administrator string) (DatabaseACL, error) {
	if original.Owner == "" || administrator == "" || len(approved) == 0 {
		return DatabaseACL{}, errors.New("exact owner and approved CA client inventory required")
	}
	result := DatabaseACL{Owner: original.Owner, Grants: []Grant{}}
	for _, g := range original.Grants {
		if g.Role == "PUBLIC" {
			if (g.Privilege != "CONNECT" && g.Privilege != "TEMPORARY") || g.Grantable {
				return DatabaseACL{}, errors.New("unexpected PUBLIC CA privilege requires separate review")
			}
			continue
		}
		result.Grants = append(result.Grants, g)
	}
	for _, access := range approved {
		if access.Role == "" || access.Role == "PUBLIC" || strings.HasPrefix(access.Role, "cloud8021x_") || (!access.Connect && !access.Temporary) {
			return DatabaseACL{}, errors.New("invalid approved CA client")
		}
		for _, privilege := range []string{"CONNECT", "TEMPORARY"} {
			if (privilege == "CONNECT" && !access.Connect) || (privilege == "TEMPORARY" && !access.Temporary) {
				continue
			}
			present := false
			for _, g := range result.Grants {
				if g.Role == access.Role && g.Privilege == privilege {
					present = true
				}
			}
			if !present {
				result.Grants = append(result.Grants, Grant{Grantor: administrator, Role: access.Role, Privilege: privilege})
			}
		}
	}
	return normalizeACL(result), nil
}
