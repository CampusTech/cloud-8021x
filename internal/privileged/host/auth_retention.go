package host

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"golang.org/x/sys/unix"
)

const authGenerationRoot = transactionRoot + "/auth-generations"
const authDirectory = "/var/log/freeradius/auth"

var authGenerationPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type AuthGeneration struct {
	Generation, Previous, Reference, ModuleSHA256 string
	Producer                                      writerPID
	ClosedPrevious                                bool
}

func nativeAuthGeneration() (string, string, error) {
	f, e := rootFile(radiusDirectory+"/mods-enabled/auth_detail", 64<<10)
	if e != nil {
		return "", "", e
	}
	defer func() { _ = f.Close() }()
	raw, e := io.ReadAll(f)
	if e != nil {
		return "", "", e
	}
	matches := regexp.MustCompile(`(?m)^ filename = "/var/log/freeradius/auth/auth-([a-f0-9]{32})-%Y%m%d%H.detail"$`).FindAllSubmatch(raw, -1)
	if len(matches) != 1 {
		return "", "", errors.New("native auth generation is not fixed and distinct")
	}
	return string(matches[0][1]), digestBytes(raw), nil
}
func (b *RadiusBackend) nativeProducer(ctx context.Context) (writerPID, error) {
	out, e := b.command(ctx, "/usr/bin/systemctl", "show", "freeradius.service", "--property=MainPID", "--value")
	if e != nil {
		return writerPID{}, e
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(out)))
	if e != nil || pid <= 0 {
		return writerPID{}, errors.New("active native producer PID unavailable")
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return writerPID{}, e
	}
	for _, p := range processes {
		if p.PID == pid {
			args := strings.Split(strings.TrimSuffix(p.Args, "\x00"), "\x00")
			if len(args) != 2 || args[0] != "/usr/sbin/freeradius" || args[1] != "-f" {
				return writerPID{}, errors.New("native process does not match fixed protected unit")
			}
			return writerPID{p.PID, p.Start}, nil
		}
	}
	return writerPID{}, errors.New("native producer identity unavailable")
}
func readAuthGeneration(generation string) (AuthGeneration, error) {
	var out AuthGeneration
	if !authGenerationPattern.MatchString(generation) {
		return out, errors.New("invalid auth generation")
	}
	raw, e := readPrivateCache(filepath.Join(authGenerationRoot, generation+".json"), 4096)
	if e != nil {
		return out, e
	}
	if domain.DecodeJSONStrict(raw, &out) != nil || out.Generation != generation || !authGenerationPattern.MatchString(out.Reference) || len(out.ModuleSHA256) != 64 || out.Producer.PID <= 0 || out.Producer.Start == 0 || (out.Previous != "" && !authGenerationPattern.MatchString(out.Previous)) || out.Previous == generation {
		return out, errors.New("invalid protected auth generation record")
	}
	data, e := readPrivateCache(filepath.Join(transactionRoot, out.Reference, "receipt.json"), 64<<20)
	if e != nil {
		return out, e
	}
	var receipt Receipt
	if domain.DecodeJSONStrict(data, &receipt) != nil || receipt.Phase != "complete" || receipt.ID != out.Reference || receipt.WriterRetirement == nil || receipt.WriterRetirement.Native["mods-enabled/auth_detail"] != out.ModuleSHA256 {
		return out, errors.New("auth generation lacks completed native attestation")
	}
	return out, nil
}

// CaptureAuthGeneration is read-only and runs before replacement of the old
// native tree. A reboot/manual restart without a protected activation receipt
// cannot manufacture closure; callers retain all uncertain generations.
func CaptureAuthGeneration(ctx context.Context, b *RadiusBackend) (*AuthGeneration, error) {
	generation, module, e := nativeAuthGeneration()
	if e != nil {
		return nil, e
	}
	original, e := readAuthGeneration(generation)
	if e != nil {
		return nil, e
	}
	if original.ModuleSHA256 != module {
		return nil, errors.New("native auth module differs from protected activation")
	}
	producer, e := b.nativeProducer(ctx)
	if e != nil {
		return nil, e
	}
	if original.Producer != producer {
		return nil, errors.New("native producer differs from protected activation")
	}
	return &original, nil
}

// CompleteAuthGeneration follows successful new native activation and completed
// installation. It binds the distinct generated module to the actual new PID.
func CompleteAuthGeneration(ctx context.Context, b *RadiusBackend, reference, generation string, prior *AuthGeneration) error {
	if os.Geteuid() != 0 || !authGenerationPattern.MatchString(reference) || !authGenerationPattern.MatchString(generation) {
		return errors.New("root completed auth activation required")
	}
	actual, module, e := nativeAuthGeneration()
	if e != nil || actual != generation {
		return errors.New("effective auth module differs from new generation")
	}
	producer, e := b.nativeProducer(ctx)
	if e != nil {
		return e
	}
	out := AuthGeneration{Generation: generation, Reference: reference, ModuleSHA256: module, Producer: producer}
	if prior != nil {
		if prior.Generation == generation || producer == prior.Producer {
			return errors.New("new native activation is not distinct")
		}
		processes, e := scanWriterProcesses()
		if e != nil {
			return e
		}
		for _, p := range processes {
			if p.PID == prior.Producer.PID && p.Start == prior.Producer.Start {
				return errors.New("previous native producer remains active")
			}
		}
		out.Previous = prior.Generation
		out.ClosedPrevious = true
	}
	if e = protectedDirectory(authGenerationRoot, 0, 0, 0700); e != nil {
		return e
	}
	raw, e := json.Marshal(out)
	if e != nil {
		return e
	}
	path := filepath.Join(authGenerationRoot, generation+".json")
	if existing, e := readPrivateCache(path, 4096); e == nil {
		if string(existing) != string(raw) {
			return errors.New("auth activation evidence differs")
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = privateWrite(path, raw, 0600); e != nil {
		return e
	}
	return syncWriterDirectory(authGenerationRoot)
}
func proveNativeProcessesGone(uid int) error {
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	for _, p := range processes {
		var st unix.Stat_t
		if e = unix.Stat(filepath.Join("/proc", strconv.Itoa(p.PID)), &st); errors.Is(e, unix.ENOENT) {
			continue
		} else if e != nil {
			return e
		}
		args := strings.Split(p.Args, "\x00")
		if int(st.Uid) == uid || (len(args) > 0 && (filepath.Base(args[0]) == "freeradius" || filepath.Base(args[0]) == "radiusd")) {
			return errors.New("native process still present during auth cleanup")
		}
	}
	return nil
}

// PruneClosedAuthGenerations is invoked only during an already required stopped
// native interval. It never stops/restarts a service itself. The replacement and
// rollback generation are excluded even when an older closure record exists.
func PruneClosedAuthGenerations(ctx context.Context, b *RadiusBackend, host, next, rollback string, a Accounts, store auth.CursorBatch) (auth.RetentionResult, error) {
	out := auth.RetentionResult{}
	if os.Geteuid() != 0 || !authGenerationPattern.MatchString(next) {
		return out, errors.New("root exact generation cleanup required")
	}
	active, e := b.Running(ctx)
	if e != nil || active {
		return out, errors.New("native stop not proven")
	}
	if e = proveNativeProcessesGone(a.NativeUID); e != nil {
		return out, e
	}
	if e = protectedDirectory(authGenerationRoot, 0, 0, 0700); e != nil {
		return out, e
	}
	d, e := os.Open(authGenerationRoot)
	if e != nil {
		return out, e
	}
	names, e := d.Readdirnames(4097)
	_ = d.Close()
	if (e != nil && !errors.Is(e, io.EOF)) || len(names) > 4096 {
		return out, errors.New("protected auth generations exceed bound")
	}
	closed := map[string]bool{}
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") {
			return out, errors.New("unknown protected generation entry")
		}
		record, e := readAuthGeneration(strings.TrimSuffix(name, ".json"))
		if e != nil {
			return out, e
		}
		if record.ClosedPrevious && record.Previous != rollback && record.Previous != next {
			closed[record.Previous] = true
		}
	}
	reader, e := auth.New(auth.Options{Directory: authDirectory, Host: host, ProducerUID: a.NativeUID, EventGID: a.EventsGID, Store: retentionReadStore{store}})
	if e != nil {
		return out, e
	}
	defer func() { _ = reader.Close() }()
	return reader.PruneClosed(ctx, closed, store)
}

type retentionReadStore struct{ auth.CursorBatch }

func (s retentionReadStore) Cursor(ctx context.Context, source string) (string, error) {
	rows, e := s.AuthCursors(ctx, []string{source})
	return rows[source], e
}
func (retentionReadStore) AuthEvent(context.Context, string, string, string, string, json.RawMessage) error {
	return errors.New("retention cannot create auth events")
}

func CurrentAuthGeneration() (string, error) {
	generation, _, e := nativeAuthGeneration()
	return generation, e
}
