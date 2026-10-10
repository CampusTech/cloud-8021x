package main

import "errors"

// The caller provides only two fixed private directory descriptors. No source
// names or user paths are accepted. Failure retains every earlier exclusive file.
func publishPreparedNAS(b preparedNAS, write func(string, string, []byte) error) error {
	if write == nil {
		return errors.New("fixed publication writer required")
	}
	if e := validatePreparedNAS(b); e != nil {
		return e
	}
	for _, name := range nasMaterialNames {
		if e := write("materials", name, b.Materials[name]); e != nil {
			return e
		}
	}
	for _, name := range producerCases {
		if e := write("plans", name+".json", b.Plans[name+".json"]); e != nil {
			return e
		}
	}
	return nil
}
func validatePreparedNAS(b preparedNAS) error {
	if len(b.Materials) != 13 || len(b.Plans) != 9 {
		return errors.New("complete exclusive fixed publication required")
	}
	for _, name := range nasMaterialNames {
		if len(b.Materials[name]) == 0 || len(b.Materials[name]) > 64<<10 {
			return errors.New("closed bounded material absent")
		}
	}
	for _, name := range producerCases {
		if len(b.Plans[name+".json"]) == 0 || len(b.Plans[name+".json"]) > 64<<10 {
			return errors.New("closed bounded plan absent")
		}
	}
	return nil
}
