{
	"subject": {
		"commonName": {{ toJson .Subject.CommonName }},
		"organizationalUnit": {{ toJson .Insecure.CR.Subject.OrganizationalUnit }}
	},
	"sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["clientAuth"]
}
