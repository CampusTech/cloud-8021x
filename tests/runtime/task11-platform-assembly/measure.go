package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

const baseQueryFormat = "${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"

type baseLoopFact struct {
	Path         string
	Major, Minor uint32
	Occupied     bool
	Backing      backingIdentity
}

type baseObservations struct {
	Schema                              int
	ObservedAt                          time.Time
	BaselineSHA256, LowerManifestSHA256 string
	Tools                               map[string]pin
	ProjectedFileBytes                  int64
	ProjectedEntries                    int
	FreeBytes, FreeInodes               int64
	Loops                               []baseLoopFact
	FreeLoopDevices                     []string
}

// Only failures from the fixed public measurement action may be diagnosed.
// Business-stage failures never acquire this marker.
type baseMeasurementError struct{ cause error }

func (e *baseMeasurementError) Error() string { return e.cause.Error() }
func (e *baseMeasurementError) Unwrap() error { return e.cause }

var baseOutputNames = []string{"base-after-prereqs.txt", "lower-source.json", "base-observations.json"}

func measureCommand() *cobra.Command { return measureCommandWith(measureBase) }
func measureCommandWith(run func(context.Context) error) *cobra.Command {
	var dry, debug bool
	c := &cobra.Command{Use: "measure-base", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, RunE: func(cmd *cobra.Command, _ []string) error {
		if parent := cmd.Parent(); parent != nil && (parent.Flags().Changed("plan-sha256") || parent.Flags().Changed("primitive-result-sha256")) {
			return errors.New("measurement does not accept stage pins")
		}
		if dry {
			// Pure declaration: no guest guard, descriptor, query, lock or publication.
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Operation string
				Query     []string
				Tools     map[string]string
				Outputs   []string
			}{"measure-base", []string{"-W", "-f=" + baseQueryFormat}, toolPaths, baseOutputNames})
		}
		if debug {
			logrus.WithFields(logrus.Fields{"operation": "measure-base", "tools": len(toolPaths)}).Info("development base observation")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Minute)
		defer cancel()
		if err := run(ctx); err != nil {
			return &baseMeasurementError{cause: err}
		}
		return nil
	}}
	c.Flags().BoolVar(&dry, "dry-run", false, "Print the closed measurement plan without filesystem or process access")
	c.Flags().BoolVar(&debug, "debug", false, "Log public measurement counts only")
	return c
}

func validateBaseQuery(raw, audit []byte) error {
	if len(raw) > 1<<20 || !bytesEndNewline(raw) || len(audit) > 1<<20 || strings.TrimSpace(string(audit)) != "" {
		return errors.New("bounded complete inventory and empty audit required")
	}
	rows := strings.Split(string(raw[:len(raw)-1]), "\n")
	if len(rows) != 347 {
		return errors.New("actual347 package rows required")
	}
	seen := map[string]bool{}
	for _, row := range rows {
		f := strings.Split(row, "\t")
		if len(f) != 4 || f[0] == "" || f[1] == "" || (f[2] != "arm64" && f[2] != "all") || (f[3] != "ii " && f[3] != "hi ") || seen[f[0]] || strings.ContainsAny(row, "\r\x00") {
			return errors.New("actual package identity or installed state differs")
		}
		seen[f[0]] = true
	}
	return nil
}
func bytesEndNewline(b []byte) bool { return len(b) > 0 && b[len(b)-1] == '\n' }

func measuredLoopPair(facts []baseLoopFact) ([]string, error) {
	if len(facts) > 1000 {
		return nil, errors.New("loop observations exceed bound")
	}
	seen := map[string]bool{}
	var free []string
	for _, f := range facts {
		n, err := strconv.Atoi(strings.TrimPrefix(f.Path, "/dev/loop"))
		if err != nil || n < 0 || n > 999 || f.Path != fmt.Sprintf("/dev/loop%d", n) || f.Major != 7 || f.Minor != uint32(n) || seen[f.Path] {
			return nil, errors.New("actual loop device identity differs")
		}
		seen[f.Path] = true
		if !f.Occupied {
			free = append(free, f.Path)
		}
	}
	sort.Slice(free, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(free[i], "/dev/loop"))
		b, _ := strconv.Atoi(strings.TrimPrefix(free[j], "/dev/loop"))
		return a < b
	})
	if len(free) < 2 {
		return nil, errors.New("two existing free loop observations required")
	}
	return free[:2], nil
}

func measureBase(ctx context.Context) error {
	if err := observePlatform(false); err != nil {
		return err
	}
	output := controlRoot + "/base-observations.json"
	fd, err := parent(output, true)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&07777 != 0700 {
		return errors.New("fixed private measurement directory required")
	}
	for _, n := range baseOutputNames {
		if err = unix.Fstatat(fd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
			return errors.New("prior or uncertain base measurement exists")
		}
	}
	tools := map[string]pin{}
	for n, p := range toolPaths {
		h, err := measureBaseTool(ctx, p)
		if err != nil {
			return fmt.Errorf("measure fixed tool %s: %w", n, err)
		}
		tools[n] = pin{p, h}
	}
	baseline, err := executePinned(ctx, tools["dpkg-query"], []string{"-W", "-f=" + baseQueryFormat}, nil)
	if err != nil {
		return err
	}
	audit, err := executePinned(ctx, tools["dpkg"], []string{"--audit"}, nil)
	if err != nil {
		return err
	}
	if err = validateBaseQuery(baseline, audit); err != nil {
		return err
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	lower, err := measureLowerAt(ctx, root, 200000, 1664*MiB)
	_ = unix.Close(root)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(lower)
	if err != nil || len(raw) > 32<<20 {
		return errors.New("lower metadata exceeds bound")
	}
	loops, err := measureBaseLoops(ctx)
	if err != nil {
		return err
	}
	pair, err := measuredLoopPair(loops)
	if err != nil {
		return err
	}
	free, inodes, err := measuredFree()
	if err != nil {
		return err
	}
	o := baseObservations{Schema: 1, ObservedAt: time.Now().UTC(), BaselineSHA256: digest(baseline), LowerManifestSHA256: digest(raw), Tools: tools, ProjectedEntries: len(lower.Entries), FreeBytes: free, FreeInodes: inodes, Loops: loops, FreeLoopDevices: pair}
	for _, e := range lower.Entries {
		if e.Kind == "file" {
			o.ProjectedFileBytes += e.Bytes
		}
	}
	observations, err := json.Marshal(o)
	if err != nil || len(observations) > 1<<20 {
		return errors.New("base observations exceed bound")
	}
	for i, b := range [][]byte{baseline, raw, observations} {
		if err = ctx.Err(); err != nil {
			return errors.New("base measurement deadline exceeded")
		}
		if err = publishBaseAt(fd, controlRoot+"/"+baseOutputNames[i], b); err != nil {
			return err
		}
	}
	return nil
}

func publishBaseAt(fd int, path string, b []byte) error {
	if err := checkParentBinding(fd, path); err != nil {
		return err
	}
	leaf, err := unix.Openat(fd, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("exclusive base observation refused")
	}
	f := os.NewFile(uintptr(leaf), "private-base-observation")
	if err = unix.Fchmod(leaf, 0600); err == nil {
		var n int
		n, err = f.Write(b)
		if err == nil && n != len(b) {
			err = errors.New("short base observation")
		}
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("incomplete base observation retained")
	}
	if err = unix.Fsync(fd); err != nil {
		return err
	}
	return checkParentBinding(fd, path)
}
