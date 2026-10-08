package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Store interface {
	Cursor(context.Context, string) (string, error)
	AuthEvent(context.Context, string, string, string, string, json.RawMessage) error
}
type Event struct {
	Serial           string    `json:"serial"`
	ID               string    `json:"event_id"`
	Event            string    `json:"event"`
	Host             string    `json:"host"`
	Received         time.Time `json:"received_at"`
	Client           string    `json:"client_id"`
	Location         string    `json:"location_id"`
	Source           string    `json:"src_ip"`
	Station          string    `json:"calling_station_id"`
	Called           string    `json:"called_station_id"`
	NASPortTypes     []string  `json:"nas_port_types"`
	NASPortTypeCount int       `json:"nas_port_type_count"`
	Reason           string    `json:"reason"`
	DeviceID         string    `json:"device_id"`
	DeviceOwner      string    `json:"device_owner"`
	DeviceName       string    `json:"device_name"`
	DeviceModel      string    `json:"device_model"`
	Fingerprint      string    `json:"certificate_fingerprint"`
	VLANID           string    `json:"vlan_id"`
	APName           string    `json:"ap_name"`
	SiteName         string    `json:"site_name"`
	VLANName         string    `json:"vlan_name"`
}
type Options struct {
	Directory, Host       string
	ProducerUID, EventGID int
	Store                 Store
	// Enrich reads immutable local inventory/metadata and verified Class only.
	Enrich              func(*Event, Record)
	MaxFiles, MaxEvents int
}
type Reader struct {
	mu        sync.Mutex
	directory *os.File
	options   Options
}

var filename = regexp.MustCompile(`^auth-[a-f0-9]{16,64}-[0-9]{10}\.detail$`)

func New(o Options) (*Reader, error) { return newReader(o, true) }
func newReader(o Options, strict bool) (*Reader, error) {
	if o.Host == "" || len(o.Host) > 253 || o.Store == nil || o.ProducerUID < 0 || o.EventGID < 0 || !filepath.IsAbs(o.Directory) || filepath.Clean(o.Directory) != o.Directory {
		return nil, errors.New("invalid auth reader configuration")
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = 1024
	}
	if o.MaxEvents == 0 {
		o.MaxEvents = 256
	}
	if o.MaxFiles < 1 || o.MaxFiles > 4096 || o.MaxEvents < 1 || o.MaxEvents > 4096 {
		return nil, errors.New("invalid auth reader bounds")
	}
	fd, err := unix.Open("/", unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(o.Directory, "/"), "/")
	for i, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return nil, errors.New("auth directory unavailable")
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			_ = unix.Close(fd)
			return nil, errors.New("auth directory invalid")
		}
		valid := true
		if i == len(parts)-1 {
			valid = int(st.Uid) == o.ProducerUID && int(st.Gid) == o.EventGID && st.Mode&0777 == 0750
		} else if strict {
			valid = st.Uid == 0 && st.Mode&0022 == 0
		}
		if !valid {
			_ = unix.Close(fd)
			return nil, errors.New("unsafe auth directory ownership or permissions")
		}
	}
	return &Reader{directory: os.NewFile(uintptr(fd), o.Directory), options: o}, nil
}
func (r *Reader) Close() error { r.mu.Lock(); defer r.mu.Unlock(); return r.directory.Close() }
func (r *Reader) Poll(ctx context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// An independently opened descriptor resets directory iteration without seek races.
	fd, err := unix.Openat(int(r.directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	dir := os.NewFile(uintptr(fd), "auth")
	names, err := dir.Readdirnames(r.options.MaxFiles + 1)
	_ = dir.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	if len(names) > r.options.MaxFiles {
		return 0, errors.New("auth directory file limit exceeded")
	}
	sort.Strings(names)
	total := 0
	for _, name := range names {
		if !filename.MatchString(name) {
			continue
		}
		n, err := r.read(ctx, name, r.options.MaxEvents-total)
		total += n
		if err != nil {
			return total, err
		}
		if total >= r.options.MaxEvents {
			break
		}
	}
	return total, nil
}
func (r *Reader) read(ctx context.Context, name string, limit int) (int, error) {
	fd, err := unix.Openat(int(r.directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, errors.New("auth event file unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != r.options.ProducerUID || int(st.Gid) != r.options.EventGID || st.Mode&0777 != 0640 {
		return 0, errors.New("unsafe auth event file")
	}
	// The protected producer generation embedded in the filename is immutable.
	// Retained backup restoration must preserve host and filename, while inode
	// and device are transport details that change on a legitimate restore.
	source := fmt.Sprintf("%s/%s", r.options.Host, name)
	cursor, err := r.options.Store.Cursor(ctx, source)
	if err != nil {
		return 0, err
	}
	var offset int64
	if cursor != "" {
		offset, err = strconv.ParseInt(cursor, 10, 64)
		if err != nil || offset < 0 {
			return 0, errors.New("invalid committed auth cursor")
		}
	}
	if offset > st.Size {
		return 0, errors.New("auth file truncated below committed cursor")
	}
	n := 0
	for n < limit {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		data := make([]byte, MaxRecord+1)
		size, e := f.ReadAt(data, offset)
		if e != nil && !errors.Is(e, io.EOF) {
			return n, e
		}
		record, consumed, e := Parse(data[:size])
		if e != nil {
			return n, e
		}
		if consumed == 0 {
			return n, nil
		}
		one := func(key string) string {
			v := record.Values[key]
			if len(v) == 1 {
				return v[0]
			}
			return ""
		}
		receipt, e := strconv.ParseInt(one("C8021X-Receipt"), 10, 64)
		if e != nil || receipt <= 0 {
			return n, errors.New("invalid original auth receipt")
		}
		identity := sha256.Sum256([]byte(source + ":" + strconv.FormatInt(offset, 10)))
		event := Event{ID: hex.EncodeToString(identity[:]), Event: one("Packet-Type"), Host: r.options.Host, Received: time.Unix(receipt, 0).UTC(), Client: one("C8021X-Client"), Location: one("C8021X-Location"), Source: one("C8021X-Source"), Station: one("C8021X-Station"), Called: one("C8021X-Called"), NASPortTypes: record.Values["C8021X-Port-Type"], Reason: one("C8021X-Reason"), DeviceOwner: "N/A", DeviceName: "N/A", DeviceModel: "N/A", APName: "N/A", SiteName: "N/A", VLANName: "N/A"}
		event.NASPortTypeCount, _ = strconv.Atoi(one("C8021X-Port-Count"))
		if event.Reason == "" {
			event.Reason = "native_final_outcome"
		}
		if r.options.Enrich != nil {
			r.options.Enrich(&event, record)
		}
		payload, e := json.Marshal(event)
		if e != nil {
			return n, e
		}
		next := strconv.FormatInt(offset+int64(consumed), 10)
		if e = r.options.Store.AuthEvent(ctx, source, cursor, next, event.ID, payload); e != nil {
			return n, e
		}
		offset += int64(consumed)
		cursor = next
		n++
	}
	return n, nil
}
