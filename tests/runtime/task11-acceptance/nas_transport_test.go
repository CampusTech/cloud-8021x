package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func nasTestEnrollment() enrollment { return enrollment{ControllerSHA256: strings.Repeat("a", 64)} }
func TestNASDescriptorClosedInvocation(t *testing.T) {
	pin := strings.Repeat("b", 64)
	for _, action := range []string{"admit", "nas-native", "nas-ongoing", "nas-duplicates", "nas-outage", "nas-ca-original", "nas-ca-adopted", "nas-ca-passive"} {
		t.Run(action, func(t *testing.T) {
			got, err := nasTransportInvocation(nasTestEnrollment(), pin, action, 3)
			if err != nil {
				t.Fatal("valid fixed descriptor invocation refused", err)
			}
			if !reflect.DeepEqual(got.entry, []string{"/proc/self/fd/6", "nas-descriptor", action, pin}) {
				t.Fatal("entry can select a path, descriptor or extra target", got.entry)
			}
			want := []string{nasHelper, "nas", action}
			limit, timeout := sc.MaxResultBytes, 10*time.Minute
			if action == "admit" {
				want = []string{nasHelper, "admit"}
				limit, timeout = 4096, 30*time.Second
			}
			if !reflect.DeepEqual(got.helper, want) || got.output != limit || got.timeout != timeout {
				t.Fatal("fixed helper action/output/time bounds differ", got)
			}
			a, h, err := nasEntryArguments(got.entry[2:])
			if err != nil || a != action || h != pin {
				t.Fatal("two-argument descriptor child contract differs", err)
			}
		})
	}
	for _, bad := range []struct {
		e           enrollment
		pin, action string
		size        int
	}{
		{nasTestEnrollment(), pin, "read-accounting", 1}, {nasTestEnrollment(), pin, "NAS-NATIVE", 1}, {nasTestEnrollment(), pin, "nas-native --target=other", 1},
		{nasTestEnrollment(), strings.ToUpper(pin), "admit", 1}, {enrollment{}, pin, "admit", 1}, {nasTestEnrollment(), pin, "admit", 0}, {nasTestEnrollment(), pin, "admit", nasInputLimit + 1},
	} {
		if _, err := nasTransportInvocation(bad.e, bad.pin, bad.action, bad.size); err == nil {
			t.Fatal("unsafe invocation accepted", bad)
		}
	}
	for _, args := range [][]string{{}, {"admit"}, {"admit", pin, "/other"}, {"read-ca-issued", pin}, {"admit", strings.ToUpper(pin)}, {"admit", ""}} {
		if _, _, err := nasEntryArguments(args); err == nil {
			t.Fatal("argument override accepted", args)
		}
	}
}

func nasTestFiles(t *testing.T) []*os.File {
	t.Helper()
	files := make([]*os.File, 4)
	for i := range files {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		files[i] = f
		t.Cleanup(func() { _ = f.Close() })
	}
	return files
}
func nasTestClosed(files []*os.File) bool {
	for _, f := range files {
		if _, err := f.Stat(); err == nil {
			return false
		}
	}
	return true
}
func TestNASDescriptorRetainsFilesAndExactOpaqueInput(t *testing.T) {
	files := nasTestFiles(t)
	checks, captures, runs := 0, 0, 0
	pin := strings.Repeat("b", 64)
	input := []byte(" private opaque stdin with whitespace\n")
	out, err := runNASDescriptor(context.Background(), nasTestEnrollment(), pin, "nas-native", input, func(e enrollment, p string) (*nasDescriptors, error) {
		captures++
		if e.ControllerSHA256 != strings.Repeat("a", 64) || p != pin {
			t.Fatal("capture pins changed")
		}
		return &nasDescriptors{files: files, recheck: func() error { checks++; return nil }}, nil
	}, func(_ context.Context, args []string, in []byte, limit int, timeout time.Duration, fds []*os.File) ([]byte, error) {
		runs++
		if checks != 1 || !reflect.DeepEqual(fds, files) || !bytes.Equal(in, input) || limit != sc.MaxResultBytes || timeout != 10*time.Minute || args[0] != "/proc/self/fd/6" {
			t.Fatal("descriptor/input/bounds not retained")
		}
		return []byte("public-body"), nil
	})
	if err != nil || string(out) != "public-body" || captures != 1 || runs != 1 || checks != 2 || !nasTestClosed(files) {
		t.Fatal("retained descriptor success contract differs", err, checks, captures, runs)
	}
}
func TestNASDescriptorRefusesUncertaintyAndClosesAllFiles(t *testing.T) {
	for _, phase := range []string{"capture", "before", "run", "after", "overflow", "alias", "missing-check"} {
		t.Run(phase, func(t *testing.T) {
			files := nasTestFiles(t)
			visible := []byte("private helper diagnostic")
			checks, runs := 0, 0
			capture := func(enrollment, string) (*nasDescriptors, error) {
				d := &nasDescriptors{files: files, recheck: func() error {
					checks++
					if (phase == "before" && checks == 1) || (phase == "after" && checks == 2) {
						return errors.New("private path changed")
					}
					return nil
				}}
				if phase == "alias" {
					_ = d.files[1].Close()
					d.files[1] = d.files[0]
				}
				if phase == "missing-check" {
					d.recheck = nil
				}
				if phase == "capture" {
					return d, errors.New("private input path")
				}
				return d, nil
			}
			out, err := runNASDescriptor(context.Background(), nasTestEnrollment(), strings.Repeat("b", 64), "admit", []byte("opaque"), capture, func(context.Context, []string, []byte, int, time.Duration, []*os.File) ([]byte, error) {
				runs++
				if phase == "run" {
					return visible, errors.New("secret stderr")
				}
				if phase == "overflow" {
					return bytes.Repeat([]byte("x"), 4097), nil
				}
				return visible, nil
			})
			if err == nil || len(out) != 0 || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
				t.Fatal("uncertain/private helper output exposed", err)
			}
			if !nasTestClosed(files) {
				t.Fatal("captured descriptor leaked")
			}
			if phase == "before" || phase == "alias" || phase == "missing-check" || phase == "capture" {
				if runs != 0 {
					t.Fatal("effects preceded descriptor admission")
				}
			}
			if phase == "run" || phase == "after" {
				if !bytes.Equal(visible, make([]byte, len(visible))) {
					t.Fatal("rejected output not cleared")
				}
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := runNASDescriptor(cancelled, nasTestEnrollment(), strings.Repeat("b", 64), "admit", []byte("opaque"), func(enrollment, string) (*nasDescriptors, error) { called = true; return nil, nil }, nil)
	if err == nil || called {
		t.Fatal("cancelled transport captured descriptors")
	}
}

// Synthetic ELF headers are parser inputs only, never runnable helper binaries.
func nasTestELF() []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 3})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 183)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	return b
}
func TestNASDescriptorPinnedELFRequiresStaticExactSafeFile(t *testing.T) {
	root := recordFixture(t)
	path := filepath.Join(root, "helper")
	good := nasTestELF()
	write := func(raw []byte, mode os.FileMode) *os.File {
		t.Helper()
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	file := write(good, 0755)
	if err := nasPinnedELF(file, adoption.Digest(good), os.Geteuid()); err != nil {
		t.Fatal("pinned static ELF refused", err)
	}
	if err := nasPinnedELF(file, strings.Repeat("f", 64), os.Geteuid()); err == nil {
		t.Fatal("changed helper pin accepted")
	}
	for name, raw := range map[string][]byte{"script": []byte("#!/bin/sh\n"), "foreign": append([]byte(nil), good...), "interpreter": append(append([]byte(nil), good...), make([]byte, 56)...)} {
		if name == "foreign" {
			binary.LittleEndian.PutUint16(raw[18:], 62)
		}
		if name == "interpreter" {
			binary.LittleEndian.PutUint64(raw[32:], 64)
			binary.LittleEndian.PutUint16(raw[54:], 56)
			binary.LittleEndian.PutUint16(raw[56:], 1)
			binary.LittleEndian.PutUint32(raw[64:], 3)
		}
		if err := nasPinnedELF(write(raw, 0755), adoption.Digest(raw), os.Geteuid()); err == nil {
			t.Fatal("unpinned interpreter or foreign ELF accepted", name)
		}
	}
	for _, mode := range []os.FileMode{0777, 0644, 0755 | os.ModeSetuid} {
		if err := nasPinnedELF(write(good, mode), adoption.Digest(good), os.Geteuid()); err == nil {
			t.Fatal("unsafe executable mode accepted", mode)
		}
	}
	file = write(good, 0755)
	if err := os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if err := nasPinnedELF(file, adoption.Digest(good), os.Geteuid()); err == nil {
		t.Fatal("multiply linked helper accepted")
	}
}

func TestNASDescriptorProcRequiresExactReadonlyMountIdentity(t *testing.T) {
	good := []byte("37 23 0:5 / " + nasRoot + "/proc ro,nosuid,nodev,noexec,relatime - proc proc rw\n")
	id, err := nasProcMountIdentity(good, "0:5")
	if err != nil || id.ID != "37" || id.Parent != "23" || id.Device != "0:5" || id.Root != "/" {
		t.Fatal("fixed real readonly proc mount refused", err)
	}
	for _, raw := range [][]byte{
		nil, bytes.Replace(good, []byte(" ro,"), []byte(" rw,"), 1), bytes.Replace(good, []byte("nosuid,"), nil, 1), bytes.Replace(good, []byte("nodev,"), nil, 1),
		bytes.Replace(good, []byte("- proc proc"), []byte("- tmpfs tmpfs"), 1), bytes.Replace(good, []byte(" / "), []byte(" /other "), 1),
		bytes.Replace(good, []byte(nasRoot+"/proc"), []byte(nasRoot+"/other"), 1), append(append([]byte(nil), good...), good...),
		append(append([]byte(nil), good...), []byte("38 37 0:6 / "+nasRoot+"/proc/self ro,nosuid,nodev - tmpfs tmpfs rw\n")...),
		bytes.Replace(good, []byte("37 "), []byte("037 "), 1), bytes.Repeat([]byte("x"), (256<<10)+1),
	} {
		if _, err := nasProcMountIdentity(raw, "0:5"); err == nil {
			t.Fatal("unsafe or ambiguous proc mount accepted")
		}
	}
	if _, err := nasProcMountIdentity(good, "0:6"); err == nil {
		t.Fatal("different actual mount device accepted")
	}
}

func TestNASDescriptorOperationRequiresActualOwnedChildGroup(t *testing.T) {
	path := "/system.slice/task11-acceptance.service/operation-" + strings.Repeat("a", 32)
	if got, err := nasOperationPath([]byte("0::" + path + "\n")); err != nil || got != path {
		t.Fatal("actual fixed operation group refused", err)
	}
	for _, raw := range []string{"0::/system.slice/task11-acceptance.service\n", "0::/other/operation-" + strings.Repeat("a", 32), "0::" + path + "\n0::" + path, "0::" + strings.ToUpper(path), "1:name=systemd:" + path, "0::" + path + "/child"} {
		if _, err := nasOperationPath([]byte(raw)); err == nil {
			t.Fatal("foreign/nonoperation cgroup accepted")
		}
	}
}

func TestNASDescriptorPublicEntriesRejectInvalidInputBeforeGuestWork(t *testing.T) {
	ctx := context.Background()
	if out, err := nasDescriptorCall(ctx, enrollment{}, "", "arbitrary", nil); err == nil || len(out) != 0 {
		t.Fatal("invalid public NAS transport input accepted")
	}
	if err := nasDescriptorEntry(ctx, []string{"admit", "", "--target=other"}); err == nil {
		t.Fatal("public child path/target override accepted")
	}
}
