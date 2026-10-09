package postgres

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"golang.org/x/sys/unix"
)

const RuntimePoolDirectory = "/run/cloud-8021x/database-pools"

// NewRuntime reserves a whole pool class before opening any database connection.
// Fixed host-created lock inodes prevent concurrent daemon/CLI observations or
// certificate jobs from multiplying the provisioned per-node connection budget.
func NewRuntime(ctx context.Context, dsn string, c config.Database, class config.RuntimePool) (*Store, error) {
	return newRuntimeAt(ctx, dsn, c, class, RuntimePoolDirectory)
}
func newRuntimeAt(ctx context.Context, dsn string, c config.Database, class config.RuntimePool, directory string) (*Store, error) {
	limit, err := c.RuntimePoolLimit(class)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(directory, string(class)+".lock"), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("runtime database pool slot unavailable")
	}
	f := os.NewFile(uintptr(fd), "runtime-pool")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0007 != 0 {
		_ = f.Close()
		return nil, errors.New("runtime database pool slot identity rejected")
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = f.Close()
		return nil, errors.New("runtime database pool already reserved by a local operation")
	}
	c.MaxConnections, c.MinConnections = limit, 0
	s, err := newStore(ctx, dsn, c, false)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	var once sync.Once
	s.releasePool = func() { once.Do(func() { _ = f.Close() }) }
	return s, nil
}
