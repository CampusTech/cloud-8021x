package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/cobra"
)

func TestGPTVerifyCommandRequiresEveryIndependentPin(t *testing.T) {
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "cloud8021x-task11-gpt-verify-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	source := testGPTImage()
	p, err := planGPT(bytes.NewReader(source), bytes.NewReader(source), int64(len(source)), int64(len(source)), testGPTRandom())
	if err != nil {
		t.Fatal(err)
	}
	candidate := bytes.Clone(source)
	for _, patch := range p.Patches {
		copy(candidate[patch.Offset:], patch.After)
	}
	planBytes, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	pin := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	data := map[string][]byte{"source": source, "boot": source, "derivative": candidate, "plan": planBytes}
	flags := map[string]string{}
	for name, content := range data {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		flags[name] = path
		flags[name+"-sha256"] = pin(content)
		if name != "plan" {
			flags[name+"-size"] = strconv.Itoa(len(content))
		}
	}
	run := func(c *cobra.Command, f map[string]string) ([]byte, error) {
		var args []string
		for k, v := range f {
			args = append(args, "--"+k, v)
		}
		var out bytes.Buffer
		c.SetArgs(args)
		c.SetOut(&out)
		c.SetErr(&out)
		err := c.Execute()
		return out.Bytes(), err
	}
	out, err := run(gptVerifyCommand(), flags)
	if err != nil || !bytes.Contains(out, []byte(`"verified":true`)) {
		t.Fatalf("no full verification receipt: %v %s", err, out)
	}
	for _, flag := range []string{"source-sha256", "boot-sha256", "derivative-sha256", "plan-sha256", "source-size", "boot-size", "derivative-size"} {
		t.Run(flag, func(t *testing.T) {
			f := map[string]string{}
			for k, v := range flags {
				f[k] = v
			}
			if len(flag) > 5 && flag[len(flag)-5:] == "-size" {
				f[flag] = strconv.Itoa(len(source) + 512)
			} else {
				f[flag] = "0000000000000000000000000000000000000000000000000000000000000000"
			}
			if out, err := run(gptVerifyCommand(), f); err == nil {
				t.Fatalf("bad independent pin admitted: %s", out)
			}
		})
	}
	t.Run("alias", func(t *testing.T) {
		f := map[string]string{}
		for k, v := range flags {
			f[k] = v
		}
		f["boot"] = f["source"]
		if _, err := run(gptVerifyCommand(), f); err == nil {
			t.Fatal("source/boot alias accepted")
		}
	})
	t.Run("filesystem-byte-with-new-pin", func(t *testing.T) {
		mutated := bytes.Clone(candidate)
		mutated[100*512] ^= 1
		if err := os.WriteFile(flags["derivative"], mutated, 0600); err != nil {
			t.Fatal(err)
		}
		f := map[string]string{}
		for k, v := range flags {
			f[k] = v
		}
		f["derivative-sha256"] = pin(mutated)
		if _, err := run(gptVerifyCommand(), f); err == nil {
			t.Fatal("changed filesystem accepted with freshly supplied candidate hash")
		}
		if err := os.WriteFile(flags["derivative"], candidate, 0600); err != nil {
			t.Fatal(err)
		}
	})
	for _, extra := range []string{" {}", ` ,"unrecognized":true}`} {
		t.Run("malformed-plan"+extra, func(t *testing.T) {
			b := append(bytes.Clone(planBytes), []byte(extra)...)
			if extra != " {}" {
				b = append(bytes.Clone(planBytes[:len(planBytes)-1]), []byte(extra)...)
			}
			if err := os.WriteFile(flags["plan"], b, 0600); err != nil {
				t.Fatal(err)
			}
			f := map[string]string{}
			for k, v := range flags {
				f[k] = v
			}
			f["plan-sha256"] = pin(b)
			if _, err := run(gptVerifyCommand(), f); err == nil {
				t.Fatal("extra plan content accepted")
			}
			if err := os.WriteFile(flags["plan"], planBytes, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, expected := range data {
		actual, err := os.ReadFile(flags[name])
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("verifier mutated %s", name)
		}
	}
}
