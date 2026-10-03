module github.com/CampusTech/cloud-8021x/webhook/integration/scep

go 1.23

require (
	github.com/CampusTech/cloud-8021x/webhook v0.0.0
	github.com/smallstep/scep v0.0.0-20250318231241-a25cabb69492
)

require (
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/smallstep/pkcs7 v0.2.1 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/CampusTech/cloud-8021x/webhook => ../../webhook
