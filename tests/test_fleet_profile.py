"""The reusable Apple profile must use Fleet's native dynamic SCEP path."""
from pathlib import Path
import plistlib
import unittest
import xml.etree.ElementTree as ET


class FleetProfileTests(unittest.TestCase):
    def test_windows_profile_uses_dynamic_ndes_and_machine_certificate_store(self):
        source = (Path(__file__).resolve().parents[1] / 'examples/fleet/wifi-scep.xml').read_text()
        profile = ET.fromstring('<SyncBody>' + source + '</SyncBody>')
        values = {item.findtext('Target/LocURI').rsplit('/', 1)[-1]: item.findtext('Data')
                  for item in profile.findall('./Replace/Item')}
        self.assertEqual(values['ServerURL'], '$FLEET_VAR_NDES_SCEP_PROXY_URL')
        self.assertEqual(values['Challenge'], '$FLEET_VAR_NDES_SCEP_CHALLENGE')
        self.assertEqual(source.count(values['ServerURL']), 1)
        self.assertEqual(source.count(values['Challenge']), 1)
        self.assertEqual(values['SubjectName'], 'CN=cloud-8021x-inventory,OU=$FLEET_VAR_SCEP_RENEWAL_ID')
        self.assertNotIn('CUSTOM_SCEP', source)
        for uri in profile.findall('.//LocURI'):
            self.assertTrue(uri.text.startswith('./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/$FLEET_VAR_SCEP_WINDOWS_CERTIFICATE_ID'))
        self.assertEqual(profile[-1].tag, 'Exec')

    def test_windows_wifi_selects_machine_identity_and_pins_server_name_and_root(self):
        source = (Path(__file__).resolve().parents[1] / 'examples/fleet/wifi-8021x.xml').read_text()
        wrapper = ET.fromstring(source)
        wlan = ET.fromstring(wrapper.findtext('Item/Data'))
        self.assertEqual(wlan.findtext('.//{*}authMode'), 'machine')
        self.assertEqual(wlan.findtext('.//{*}ServerNames'), 'RADIUS_SERVER_CN')
        self.assertEqual(wlan.findtext('.//{*}AcceptServerName'), 'true')
        self.assertEqual(wlan.findtext('.//{*}PerformServerValidation'), 'true')
        self.assertEqual(wlan.findtext('.//{*}DisableUserPromptForServerValidation'), 'true')
        self.assertEqual(wlan.findtext('.//{*}TrustedRootCA'), 'ROOT_CA_THUMBPRINT')
        self.assertEqual(wlan.findtext('.//{*}IssuerHash'), 'INTERMEDIATE_CA_THUMBPRINT')

    def test_shared_profile_uses_dynamic_challenge_and_managed_renewal(self):
        source = (Path(__file__).resolve().parents[1] / 'examples/fleet/wifi-ios-byod.mobileconfig').read_text()
        profile = plistlib.loads(source.replace('RADIUS_CA_CERT_BASE64_DER', 'Y2VydA==').encode())
        payloads = {p['PayloadType']: p for p in profile['PayloadContent']}
        scep = payloads['com.apple.security.scep']
        content = scep['PayloadContent']
        self.assertEqual(content['URL'], '$FLEET_VAR_SMALLSTEP_SCEP_PROXY_URL_CANAME')
        self.assertEqual(content['Challenge'], '$FLEET_VAR_SMALLSTEP_SCEP_CHALLENGE_CANAME')
        for token in (content['URL'], content['Challenge']):
            self.assertEqual(source.count(token), 1)
        subject = dict(rdn[0] for rdn in content['Subject'])
        self.assertEqual(subject['OU'], '$FLEET_VAR_CERTIFICATE_RENEWAL_ID')
        self.assertNotIn('HARDWARE_SERIAL', source)
        self.assertFalse(content['KeyIsExtractable'])
        wifi = payloads['com.apple.wifi.managed']
        self.assertEqual(wifi['PayloadCertificateUUID'], scep['PayloadUUID'])
        self.assertFalse(wifi['EAPClientConfiguration']['TLSAllowTrustExceptions'])


if __name__ == '__main__':
    unittest.main()
