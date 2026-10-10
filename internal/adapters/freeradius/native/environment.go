package native

import "strings"

// Environment is the fixed service environment boundary for privileged startup.
// Drop libpq overrides and the launching root account's home so libpq cannot
// accidentally select root's credentials/certificates after dropping to freerad.
func Environment(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, value := range environ {
		key, _, _ := strings.Cut(value, "=")
		if key == "HOME" || strings.HasPrefix(key, "PG") || strings.HasPrefix(key, "LD_") {
			continue
		}
		out = append(out, value)
	}
	return out
}
