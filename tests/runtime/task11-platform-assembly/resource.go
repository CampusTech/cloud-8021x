package main

import (
	"errors"
	"strconv"
)

type toolStep struct {
	Name string
	Args []string
}

func filesystemSteps(name string, size int64) ([]toolStep, error) {
	limits := map[string]int64{"lower": 1792 * MiB, "blue-primary": 256 * MiB, "blue-secondary": 256 * MiB, "green-primary": 768 * MiB, "green-secondary": 768 * MiB, "pg": 256 * MiB, "api": 128 * MiB, "nas": 64 * MiB}
	if limits[name] == 0 || limits[name] != size {
		return nil, errors.New("unapproved backing name or allocation")
	}
	image := platformRoot + "/images/" + name + ".ext4"
	target := platformRoot + "/volumes/" + name
	return []toolStep{{"fallocate", []string{"-l", strconv.FormatInt(size, 10), image}}, {"mkfs", []string{"-t", "ext4", "-E", "nodiscard", "-q", "-m", "0", "-F", image}}, {"mount", []string{"-t", "ext4", "-o", "loop,nosuid,nodev", image, target}}}, nil
}
func validateGreenAvailable(available, app, private int64, inodes uint64) error {
	if app <= 0 || app > 160*MiB || private <= 0 || private > 128*MiB || available < 512*MiB+app+private || inodes < 4096 {
		return errors.New("actual green private backing cannot reserve collector, application and measured writes")
	}
	return nil
}
