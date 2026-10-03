"""The reusable Apple profile must use Fleet's native dynamic SCEP path."""
from pathlib import Path
import plistlib
import unittest


class FleetProfileTests(unittest.TestCase):
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
