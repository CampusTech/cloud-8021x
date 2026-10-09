package main

type nodeEnrollment struct{ MachineID, Hostname, Pin, ConfigSHA256 string }
type enrollment struct {
	Cloud                               cloudPins
	Passive                             passivePins
	Schema                              int
	ApplicationSHA256, ControllerSHA256 string
	Nodes                               map[string]nodeEnrollment
}
