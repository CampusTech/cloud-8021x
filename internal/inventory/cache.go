package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"golang.org/x/sys/unix"
)

// CachedProvider is an optional development response cache, never an authority.
// It preserves the vendor response's scope and timestamp. Expired/invalid cache
// cannot conceal a failed refresh or stamp old inventory with the current time.
type CachedProvider struct {
	Key string

	Provider domain.DeviceInventoryProvider
	Path     string
	MaxAge   time.Duration
	Now      func() time.Time
	mu       sync.Mutex
}

func (c *CachedProvider) Fetch(ctx context.Context, scope domain.InventoryScope) (domain.DeviceSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return domain.DeviceSnapshot{}, err
	}
	if c.Provider == nil || c.Path == "" || c.MaxAge <= 0 {
		return domain.DeviceSnapshot{}, errors.New("invalid inventory response cache")
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	if data, err := readCache(c.Path); err == nil {
		var cached cachedResponse
		batch := domain.DeviceSnapshot{}
		if domain.DecodeJSONStrict(data, &cached) == nil && cached.Key == c.Key {
			batch = cached.Batch
		}
		if batch.Complete && reflect.DeepEqual(batch.Scope, scope) && domain.Fresh(batch.ObservedAt, now, c.MaxAge) {
			if _, err = domain.BuildSnapshot(batch.Devices, batch.ObservedAt); err == nil {
				return batch, nil
			}
		}
	}
	batch, err := c.Provider.Fetch(ctx, scope)
	if err != nil {
		return domain.DeviceSnapshot{}, err
	}
	if !batch.Complete {
		return domain.DeviceSnapshot{}, domain.ErrIncompleteSnapshot
	}
	if !reflect.DeepEqual(batch.Scope, scope) {
		return domain.DeviceSnapshot{}, errors.New("cached provider scope mismatch")
	}
	if _, err = domain.BuildSnapshot(batch.Devices, batch.ObservedAt); err != nil {
		return domain.DeviceSnapshot{}, err
	}
	data, err := json.Marshal(cachedResponse{Key: c.Key, Batch: batch})
	if err != nil || len(data) > domain.MaxSnapshotBytes {
		return domain.DeviceSnapshot{}, errors.New("inventory response cache exceeds bound")
	}
	if err = ctx.Err(); err != nil {
		return domain.DeviceSnapshot{}, err
	}
	if err = writeCache(c.Path, data); err != nil {
		return domain.DeviceSnapshot{}, errors.New("inventory response cache publication failed")
	}
	return batch, nil
}
func readCache(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0777 != 0600 {
		return nil, errors.New("invalid response cache file")
	}
	data, err := io.ReadAll(io.LimitReader(f, domain.MaxSnapshotBytes+1))
	if err != nil || len(data) > domain.MaxSnapshotBytes {
		return nil, errors.New("invalid response cache")
	}
	return bytes.TrimSpace(data), nil
}
func writeCache(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".response-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

type cachedResponse struct {
	Key   string
	Batch domain.DeviceSnapshot
}
