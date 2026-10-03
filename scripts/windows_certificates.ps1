# Read-only machine certificate inventory. Fleet runs this script as LocalSystem.
# Only public DER is returned; private keys never leave the certificate store.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
    throw 'Certificate inventory must run as LocalSystem'
}
$store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'LocalMachine')
try {
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $certificates = @($store.Certificates | Where-Object { $_.HasPrivateKey } | ForEach-Object {
        [Convert]::ToBase64String($_.RawData)
    })
    $output = @{ version = 1; certificates = $certificates } | ConvertTo-Json -Depth 3 -Compress
    # Fleet truncates script output. Fail before printing any partial inventory.
    if ($output.Length -gt 9000) { throw 'Certificate inventory exceeds Fleet output budget' }
    [Console]::Out.WriteLine($output)
} finally {
    $store.Close()
}
