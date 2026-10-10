package host

import (
	"errors"
	"io"
	"runtime"
	"strconv"
	"strings"
)

// CheckShippingPlatform reads the distribution-owned canonical release file;
// /etc/os-release is normally a symlink and is never followed as root input.
// This check does not perform or infer an OS upgrade from Terraform metadata.
func CheckShippingPlatform() error {
	f, err := rootFile("/usr/lib/os-release", 16384)
	if err != nil {
		return errors.New("protected operating system identity unavailable")
	}
	defer func() { _ = f.Close() }()
	release, err := io.ReadAll(f)
	if err != nil {
		return errors.New("operating system identity unreadable")
	}
	return validateShippingPlatform(release, runtime.GOARCH)
}

func validateShippingPlatform(release []byte, architecture string) error {
	fields := map[string]string{}
	for _, line := range strings.Split(string(release), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || (key != "ID" && key != "VERSION_ID") {
			continue
		}
		if _, duplicate := fields[key]; duplicate {
			return errors.New("ambiguous operating system identity")
		}
		if strings.HasPrefix(value, "\"") {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return errors.New("invalid operating system identity")
			}
			value = decoded
		}
		fields[key] = value
	}
	if fields["ID"] != "debian" || fields["VERSION_ID"] != "13" || (architecture != "amd64" && architecture != "arm64") {
		return errors.New("shipping bootstrap requires Debian 13 on amd64 or arm64; complete the separately approved staged OS upgrade first")
	}
	return nil
}
