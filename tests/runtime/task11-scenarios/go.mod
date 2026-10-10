module github.com/CampusTech/cloud-8021x/integration/scenarios

go 1.27.2

require (
	github.com/CampusTech/cloud-8021x v0.0.0
	github.com/sirupsen/logrus v1.10.2
	github.com/smallstep/scep v0.0.0-20250318231241-a25cabb69492
	github.com/spf13/cobra v1.10.2
	golang.org/x/sys v0.48.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/smallstep/pkcs7 v0.2.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/crypto v0.57.0 // indirect
)

replace github.com/CampusTech/cloud-8021x => ../../..
