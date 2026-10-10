package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestNASRequiresSeventhPinnedHelper(t *testing.T) {
	p := validPlan()
	delete(p.Helpers, "task11-scenarios")
	if p.validate() == nil {
		t.Fatal("six-helper plan accepted without genuine scenario helper")
	}
	p.Helpers["task11-scenarios"] = pin{publicRoot + "/task11-scenarios", strings.Repeat("b", 64)}
	if err := p.validate(); err != nil {
		t.Fatal("complete seven-helper plan refused", err)
	}
	for _, bad := range []pin{{publicRoot + "/foreign", strings.Repeat("b", 64)}, {publicRoot + "/task11-scenarios", ""}} {
		p.Helpers["task11-scenarios"] = bad
		if p.validate() == nil {
			t.Fatal("unbound scenario helper accepted")
		}
	}
}
func TestNASBindsOnlyFixedAuthenticatedHelpers(t *testing.T) {
	p := validPlan()
	p.Helpers["task11-scenarios"] = pin{publicRoot + "/task11-scenarios", strings.Repeat("b", 64)}
	got, err := nasHelperBindings(p)
	want := []nasHelperBinding{{p.Helpers["task11-systemd-fixture"], nasRoot + "/usr/local/libexec/task11-systemd-fixture"}, {p.Helpers["task11-scenarios"], nasRoot + "/usr/local/libexec/task11-scenarios"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("fixed NAS scenario helper binding missing", got, err)
	}
	delete(p.Helpers, "task11-scenarios")
	if _, err = nasHelperBindings(p); err == nil {
		t.Fatal("missing helper produced an install plan")
	}
}
func procMount() string {
	return "90 1 0:42 / " + nasProc + " ro,nosuid,nodev,noexec,relatime - proc proc ro\n"
}
func procFacts() nasProcFacts { return nasProcFacts{"0:42", true, true, true, true, true, 123, 123} }
func TestNASProcMountIsExplicitAndMeasured(t *testing.T) {
	want := []string{"--no-canonicalize", "--types", "proc", "--options", "ro,nosuid,nodev,noexec", "proc", nasProc}
	if !reflect.DeepEqual(nasProcArguments(), want) {
		t.Fatal("fixed protected procfs mount argv absent")
	}
	if err := requireNASProcAbsent([]byte("1 0 8:1 / / rw - ext4 /dev/vda1 rw\n")); err != nil {
		t.Fatal(err)
	}
	if err := validateNASProc([]byte(procMount()), procFacts()); err != nil {
		t.Fatal("genuine measured procfs refused", err)
	}
}
func TestNASRefusesPreexistingOrUnsafeProcMounts(t *testing.T) {
	for _, raw := range []string{procMount(), procMount() + strings.Replace(procMount(), nasProc, nasProc+"/self", 1)} {
		if requireNASProcAbsent([]byte(raw)) == nil {
			t.Fatal("preexisting proc mount accepted for implicit repair")
		}
	}
	for _, raw := range []string{
		strings.Replace(procMount(), "ro,nosuid", "rw,nosuid", 1), strings.Replace(procMount(), ",nodev", "", 1), strings.Replace(procMount(), ",nosuid", "", 1), strings.Replace(procMount(), ",noexec", "", 1), strings.Replace(procMount(), "- proc proc", "- tmpfs tmpfs", 1), strings.Replace(procMount(), "0:42", "0:43", 1), strings.Replace(procMount(), "0:42 / ", "0:42 /foreign ", 1), procMount() + procMount(), procMount() + strings.Replace(procMount(), nasProc, nasProc+"/self", 1), strings.Replace(procMount(), "ro,nosuid", "ro,rw,nosuid", 1),
	} {
		if validateNASProc([]byte(raw), procFacts()) == nil {
			t.Fatal("unsafe/foreign proc mount accepted", raw)
		}
	}
	for _, change := range []func(*nasProcFacts){func(f *nasProcFacts) { f.ProcFS = false }, func(f *nasProcFacts) { f.ReadOnly = false }, func(f *nasProcFacts) { f.NoSuid = false }, func(f *nasProcFacts) { f.NoDev = false }, func(f *nasProcFacts) { f.NoExec = false }, func(f *nasProcFacts) { f.PIDNamespace++ }, func(f *nasProcFacts) { f.PIDNamespace = 0 }} {
		f := procFacts()
		change(&f)
		if validateNASProc([]byte(procMount()), f) == nil {
			t.Fatal("unmeasured procfs accepted")
		}
	}
}
func TestNASHelperMountMustBeReadonlyAndExact(t *testing.T) {
	target := nasRoot + "/usr/local/libexec/task11-scenarios"
	raw := "91 1 8:2 /control/public/task11-scenarios " + target + " ro,relatime - ext4 /dev/vda2 rw\n"
	if err := validateNASHelperMount([]byte(raw), target, "8:2"); err != nil {
		t.Fatal("retained readonly helper mount refused", err)
	}
	for _, bad := range []string{strings.Replace(raw, "ro,relatime", "rw,relatime", 1), raw + raw, strings.Replace(raw, "8:2", "8:3", 1), raw + strings.Replace(raw, target, target+"/foreign", 1)} {
		if validateNASHelperMount([]byte(bad), target, "8:2") == nil {
			t.Fatal("foreign/writable/ambiguous helper mount accepted")
		}
	}
}
