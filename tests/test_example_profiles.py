"""Client templates must pin the RADIUS identity, not merely trust its CA."""
from pathlib import Path
import plistlib
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1] / 'examples'


class ExampleProfileTests(unittest.TestCase):
    def test_fleet_acme_preserves_serial_identity_and_renewal_tracking(self):
        source = (ROOT / 'fleet/wifi-acme.mobileconfig').read_text()
        profile = plistlib.loads(source.replace('CA_CERT_PEM', 'AA==').encode())
        acme = next(p for p in profile['PayloadContent'] if p['PayloadType'] == 'com.apple.security.acme')
        subject = dict(rdn[0] for rdn in acme['Subject'])
        self.assertEqual(subject['CN'], acme['ClientIdentifier'])
        self.assertEqual(subject.get('OU'), '$FLEET_VAR_CERTIFICATE_RENEWAL_ID')
        self.assertTrue(acme['HardwareBound'])
        self.assertTrue(acme['Attest'])

    def test_apple_identity_references_and_server_trust(self):
        for path in ROOT.rglob('*.mobileconfig'):
            with self.subTest(profile=str(path.relative_to(ROOT))):
                source = path.read_text().replace('CA_CERT_PEM', 'AA==')
                source = source.replace('RADIUS_CA_CERT_BASE64_DER', 'AA==')
                profile = plistlib.loads(source.encode())
                payloads = {p['PayloadUUID']: p for p in profile['PayloadContent']}
                self.assertEqual(len(payloads), len(profile['PayloadContent']))
                wifi = next(p for p in payloads.values() if p['PayloadType'] == 'com.apple.wifi.managed')
                identity = payloads[wifi['PayloadCertificateUUID']]
                self.assertIn(identity['PayloadType'], ('com.apple.security.acme', 'com.apple.security.scep'))
                eap = wifi['EAPClientConfiguration']
                self.assertEqual(eap['AcceptEAPTypes'], [13])
                for anchor in eap['PayloadCertificateAnchorUUID']:
                    self.assertEqual(payloads[anchor]['PayloadType'], 'com.apple.security.root')
                self.assertEqual(eap.get('TLSTrustedServerNames'), ['RADIUS_SERVER_CN'])
                self.assertIs(eap.get('TLSAllowTrustExceptions'), False)

    def test_windows_server_trust_and_matching_certificate_store(self):
        for variant, scope, mode in [('fleet', 'Device', 'machine'), ('scep', 'User', 'user')]:
            with self.subTest(variant=variant):
                wrapper = ET.fromstring((ROOT / variant / 'wifi-8021x.xml').read_text())
                wlan = ET.fromstring(wrapper.findtext('Item/Data'))
                self.assertEqual(wlan.findtext('.//{*}authMode'), mode)
                self.assertEqual(wlan.findtext('.//{*}ServerNames'), 'RADIUS_SERVER_CN')
                for element in ('AcceptServerName', 'PerformServerValidation', 'DisableUserPromptForServerValidation'):
                    self.assertEqual(wlan.findtext('.//{*}' + element), 'true')
                self.assertEqual(wlan.findtext('.//{*}TrustedRootCA'), 'ROOT_CA_THUMBPRINT')
                self.assertEqual(wlan.findtext('.//{*}IssuerHash'), 'INTERMEDIATE_CA_THUMBPRINT')
                scep = ET.fromstring('<SyncBody>' + (ROOT / variant / 'wifi-scep.xml').read_text() + '</SyncBody>')
                for uri in scep.findall('.//LocURI'):
                    self.assertTrue(uri.text.startswith('./' + scope + '/Vendor/MSFT/ClientCertificateInstall/SCEP/'))


if __name__ == '__main__':
    unittest.main()
