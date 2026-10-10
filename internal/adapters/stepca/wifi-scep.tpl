{
  "subject": {
{{if .Inventory}}
    "commonName": "cloud-8021x-inventory",
{{else}}
    "commonName": {{ toJson .Subject.CommonName }},
{{end}}
    "organizationalUnit": {{ toJson .Insecure.CR.Subject.OrganizationalUnit }}
  },
  "sans": [],
  "keyUsage": ["digitalSignature", "keyEncipherment"],
  "extKeyUsage": ["clientAuth"]
}
