package main

import (
	"errors"
	"strings"
	"testing"
)

func TestBothGreenActivationOrdersSeeOnlyReviewedLoopPair(t *testing.T) {
	p := validPlan()
	for _, order := range [][]int{{2, 3}, {3, 2}} {
		for _, i := range order {
			u := nodeUnit(p, p.Nodes[i])
			for _, d := range p.LoopDevices {
				if !strings.Contains(u, "DeviceAllow="+d+" rwm") || !strings.Contains(u, "--bind="+d) {
					t.Fatal("activation depends on invisible free loop")
				}
			}
			if strings.Contains(u, "block-loop") || strings.Contains(u, "--bind=/dev ") {
				t.Fatal("broad device exposure")
			}
		}
	}
}

func TestManagedRebootIsOnlyForcedExitStatus133(t *testing.T) {
	for _, n := range validPlan().Nodes {
		u := nodeUnit(validPlan(), n)
		for _, required := range []string{"--keep-unit", "Restart=no\n", "SuccessExitStatus=133\n", "RestartForceExitStatus=133\n"} {
			if !strings.Contains(u, required) {
				t.Fatalf("managed reboot contract missing %q", required)
			}
		}
		if strings.Contains(u, "Restart=always") {
			t.Fatal("unexpected failures retried")
		}
	}
}

func TestRealEpochArchiveSurvivesUnitAndNspawnBindParsing(t *testing.T) {
	p := validPlan()
	n := p.Nodes[2]
	basename := "datadog-agent_1:7.84.2-1+campus1_arm64.deb"
	source := publicRoot + "/artifacts/" + basename
	destination := "/var/cache/cloud-8021x/artifacts/" + basename
	in := inputs{Plan: p, Index: candidateIndex{References: map[string][]reference{n.Name: {{source, destination, strings.Repeat("a", 64)}}}}}
	unit := completeNodeUnit(in, n)
	var found string
	for _, word := range strings.Fields(unit) {
		if strings.Contains(word, basename) || strings.Contains(word, "datadog-agent_1") {
			found = word
			break
		}
	}
	// Independent restricted tokenizers for the actual emitted grammar, based on
	// v257 core/load-fragment.c:851,957 (UNQUOTE|CUNESCAPE), followed by
	// nspawn/nspawn-mount.c:220-258 and basic/extract-word.c:62-107,130-145.
	// The second parser has no CUNESCAPE flag: a single backslash consumes the
	// next byte literally. Compare both decoded paths with original inputs.
	arg, e := parseExecStartQuotedWord(found)
	if e != nil {
		t.Fatalf("bind must survive systemd's quoted argument layer: %v", e)
	}
	if !strings.HasPrefix(arg, "--bind-ro=") {
		t.Fatal("missing bind argument")
	}
	value := strings.TrimPrefix(arg, "--bind-ro=")
	parts := []string{}
	var part strings.Builder
	escaped := false
	for _, r := range value {
		if escaped {
			part.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ':' {
			parts = append(parts, part.String())
			part.Reset()
			continue
		}
		part.WriteRune(r)
	}
	parts = append(parts, part.String())
	if escaped || len(parts) != 2 || parts[0] != source || parts[1] != destination {
		t.Fatalf("literal epoch filenames changed: %#v", parts)
	}
}

// parseExecStartQuotedWord independently implements the quoted C escape subset
// permitted in these fixed ASCII paths. It intentionally does not call the
// renderer or strconv.Unquote; unsupported escapes/controls fail this contract.
func parseExecStartQuotedWord(word string) (string, error) {
	if len(word) < 2 || word[0] != '"' || word[len(word)-1] != '"' {
		return "", errors.New("quoted ExecStart argument required")
	}
	var b strings.Builder
	for i := 1; i < len(word)-1; i++ {
		c := word[i]
		if c == '\\' {
			i++
			if i >= len(word)-1 || (word[i] != '\\' && word[i] != '"') {
				return "", errors.New("unsupported unit C escape")
			}
			c = word[i]
		} else if c == '"' || c < 32 {
			return "", errors.New("unescaped unit quote/control")
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}
