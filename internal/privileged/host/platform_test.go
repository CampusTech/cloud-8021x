package host

import "testing"

func TestDebian13ShippingPlatform(t *testing.T) {
	for _, tc := range []struct {
		name, release, architecture string
		valid                       bool
	}{
		{"trixie amd64", "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n", "amd64", true},
		{"trixie arm64", "ID=debian\nVERSION_ID=13\n", "arm64", true},
		{"bookworm", "ID=debian\nVERSION_ID=12\n", "amd64", false},
		{"ubuntu derivative", "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=13\n", "amd64", false},
		{"unknown version", "ID=debian\n", "amd64", false},
		{"duplicate version", "ID=debian\nVERSION_ID=12\nVERSION_ID=13\n", "amd64", false},
		{"bad quote", "ID=debian\nVERSION_ID=\"13\n", "amd64", false},
		{"unsupported architecture", "ID=debian\nVERSION_ID=13\n", "386", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := validateShippingPlatform([]byte(tc.release), tc.architecture); (e == nil) != tc.valid {
				t.Fatalf("accepted=%v want=%v error=%v", e == nil, tc.valid, e)
			}
		})
	}
}
