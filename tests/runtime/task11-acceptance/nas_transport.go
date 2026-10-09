package main

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"golang.org/x/sys/unix"
)

const nasRoot = "/var/lib/cloud8021x-task11/aux/nas"
const nasHelper = "/usr/local/libexec/task11-scenarios"
const nasInputLimit = 256 << 10

var errNASTransport = errors.New("fixed NAS descriptor transport refused")

type nasInvocation struct {
	entry, helper []string
	output        int
	timeout       time.Duration
}
type nasDescriptors struct {
	files   []*os.File
	held    []*os.File
	recheck func() error
}
type nasCapture func(enrollment, string) (*nasDescriptors, error)
type nasRun func(context.Context, []string, []byte, int, time.Duration, []*os.File) ([]byte, error)

func nasHelperArguments(action string) ([]string, error) {
	switch action {
	case "admit":
		return []string{nasHelper, "admit"}, nil
	case "nas-native", "nas-ongoing", "nas-duplicates", "nas-outage", "nas-ca-original", "nas-ca-adopted", "nas-ca-passive":
		return []string{nasHelper, "nas", action}, nil
	default:
		return nil, errNASTransport
	}
}
func nasTransportInvocation(e enrollment, pin, action string, size int) (nasInvocation, error) {
	var p nasInvocation
	if !validSHA(e.ControllerSHA256) || !validSHA(pin) || size < 1 || size > nasInputLimit {
		return p, errNASTransport
	}
	argv, err := nasHelperArguments(action)
	if err != nil {
		return p, err
	}
	p = nasInvocation{entry: []string{"/proc/self/fd/6", "nas-descriptor", action, pin}, helper: argv, output: sc.MaxResultBytes, timeout: 10 * time.Minute}
	if action == "admit" {
		p.output, p.timeout = 4096, 30*time.Second
	}
	return p, nil
}
func nasEntryArguments(args []string) (string, string, error) {
	if len(args) != 2 || !validSHA(args[1]) {
		return "", "", errNASTransport
	}
	if _, err := nasHelperArguments(args[0]); err != nil {
		return "", "", err
	}
	return args[0], args[1], nil
}
func (d *nasDescriptors) close() {
	if d == nil {
		return
	}
	for _, f := range append(append([]*os.File(nil), d.files...), d.held...) {
		if f != nil {
			_ = f.Close()
		}
	}
}
func (d *nasDescriptors) valid() bool {
	if d == nil || len(d.files) != 4 || d.recheck == nil {
		return false
	}
	seen := map[uintptr]bool{}
	for _, f := range d.files {
		if f == nil || seen[f.Fd()] {
			return false
		}
		if _, err := f.Stat(); err != nil {
			return false
		}
		seen[f.Fd()] = true
	}
	return true
}

// Test seams supply only capture/run instrumentation. The production caller
// captures the fixed root/net/helper/self roles, then uses runNamespaceBounded;
// neither this API nor the child arguments accept paths, fd numbers or targets.
func runNASDescriptor(ctx context.Context, e enrollment, pin, action string, input []byte, capture nasCapture, run nasRun) ([]byte, error) {
	p, err := nasTransportInvocation(e, pin, action, len(input))
	if err != nil || ctx.Err() != nil || capture == nil || run == nil {
		return nil, errNASTransport
	}
	d, err := capture(e, pin)
	defer d.close()
	if err != nil || !d.valid() || d.recheck() != nil || ctx.Err() != nil {
		return nil, errNASTransport
	}
	private := bytes.Clone(input)
	defer clear(private)
	out, runErr := run(ctx, p.entry, private, p.output, p.timeout, d.files)
	boundErr := d.recheck()
	if runErr != nil || boundErr != nil || ctx.Err() != nil || len(out) > p.output {
		clear(out)
		return nil, errNASTransport
	}
	return out, nil
}

// Scripts and PT_INTERP would introduce a second executable or interpreter
// lookup. Only the exact independently pinned, root-owned static ARM64 ELF is
// permitted. A retained regular fd is rechecked around the bounded hash read.
func nasPinnedELF(file *os.File, pin string, uid int) error {
	if file == nil || !validSHA(pin) || uid < 0 {
		return errNASTransport
	}
	var before, after unix.Stat_t
	fd := int(file.Fd())
	if unix.Fstat(fd, &before) != nil || int(before.Uid) != uid || before.Nlink != 1 || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0022 != 0 || before.Mode&07000 != 0 || before.Mode&0111 == 0 || before.Size < 64 || before.Size > 256<<20 {
		return errNASTransport
	}
	first, err := file.Stat()
	if err != nil {
		return errNASTransport
	}
	if _, err = file.Seek(0, 0); err != nil {
		return errNASTransport
	}
	raw, err := boundedInput(file, 256<<20)
	defer clear(raw)
	last, statErr := file.Stat()
	if err != nil || statErr != nil || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink || before.Size != after.Size || !os.SameFile(first, last) || !first.ModTime().Equal(last.ModTime()) || adoption.Digest(raw) != pin {
		return errNASTransport
	}
	image, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return errNASTransport
	}
	defer func() { _ = image.Close() }()
	if image.Class != elf.ELFCLASS64 || image.Data != elf.ELFDATA2LSB || image.Machine != elf.EM_AARCH64 || (image.Type != elf.ET_EXEC && image.Type != elf.ET_DYN) || (image.OSABI != elf.ELFOSABI_NONE && image.OSABI != elf.ELFOSABI_LINUX) {
		return errNASTransport
	}
	for _, p := range image.Progs {
		if p.Type == elf.PT_INTERP {
			return errNASTransport
		}
	}
	return nil
}

type nasProcIdentity struct{ ID, Parent, Device, Root, Options, SuperOptions string }

func nasDecimal(s string, positive bool) bool {
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && strconv.FormatUint(n, 10) == s && (!positive || n > 0)
}
func nasDevice(s string) bool {
	a, b, ok := strings.Cut(s, ":")
	return ok && nasDecimal(a, false) && nasDecimal(b, false)
}
func nasProcMountIdentity(raw []byte, device string) (nasProcIdentity, error) {
	var found nasProcIdentity
	if len(raw) == 0 || len(raw) > 256<<10 || !nasDevice(device) {
		return found, errNASTransport
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return found, errNASTransport
		}
		point := fields[4]
		if strings.HasPrefix(point, nasRoot+"/proc/") {
			return found, errNASTransport
		}
		if point != nasRoot+"/proc" {
			continue
		}
		count++
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if count != 1 || separator < 6 || len(fields) != separator+4 || !nasDecimal(fields[0], true) || !nasDecimal(fields[1], true) || fields[2] != device || fields[3] != "/" || fields[separator+1] != "proc" || fields[separator+2] != "proc" {
			return found, errNASTransport
		}
		options := map[string]bool{}
		for _, option := range strings.Split(fields[5], ",") {
			if option == "" || options[option] {
				return found, errNASTransport
			}
			options[option] = true
		}
		if !options["ro"] || options["rw"] || !options["nosuid"] || !options["nodev"] {
			return found, errNASTransport
		}
		found = nasProcIdentity{fields[0], fields[1], fields[2], fields[3], fields[5], fields[separator+3]}
	}
	if count != 1 {
		return found, errNASTransport
	}
	return found, nil
}

var nasOperationPattern = regexp.MustCompile(`^/system\.slice/task11-acceptance\.service/operation-[a-f0-9]{32}$`)

func nasOperationPath(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return "", errNASTransport
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if !strings.HasPrefix(line, "0::") || !nasOperationPattern.MatchString(strings.TrimPrefix(line, "0::")) {
		return "", errNASTransport
	}
	return strings.TrimPrefix(line, "0::"), nil
}
