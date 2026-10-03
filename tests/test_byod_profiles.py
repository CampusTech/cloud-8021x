from pathlib import Path
import plistlib
import unittest


class BYODProfileTests(unittest.TestCase):
    def test_identity_trust_and_wifi_references(self):
        root = Path(__file__).resolve().parents[1] / 'examples'
        for variant, identity in [('fleet', '$FLEET_VAR_HOST_UUID'), ('scep', 'DEVICE_IDENTIFIER')]:
            with self.subTest(variant=variant):
                source = (root / variant / 'wifi-ios-byod.mobileconfig').read_text()
                profile = plistlib.loads(source.replace('RADIUS_CA_CERT_BASE64_DER', 'AA==').encode())
                payloads = {p['PayloadType']: p for p in profile['PayloadContent']}
                scep = payloads['com.apple.security.scep']
                wifi = payloads['com.apple.wifi.managed']
                trust = payloads['com.apple.security.root']
                self.assertEqual(scep['PayloadContent']['Subject'][0], [['CN', identity]])
                self.assertFalse(scep['PayloadContent']['KeyIsExtractable'])
                self.assertEqual(wifi['PayloadCertificateUUID'], scep['PayloadUUID'])
                eap = wifi['EAPClientConfiguration']
                self.assertEqual(eap['AcceptEAPTypes'], [13])
                self.assertEqual(eap['PayloadCertificateAnchorUUID'], [trust['PayloadUUID']])
                self.assertEqual(eap['TLSTrustedServerNames'], ['RADIUS_SERVER_CN'])
                self.assertFalse(eap['TLSAllowTrustExceptions'])
                self.assertNotIn('DisableAssociationMACRandomization', wifi)
                if variant == 'fleet':
                    for variable in ('$FLEET_VAR_SMALLSTEP_SCEP_PROXY_URL_CANAME', '$FLEET_VAR_SMALLSTEP_SCEP_CHALLENGE_CANAME'):
                        self.assertEqual(source.count(variable), 1)


if __name__ == '__main__':
    unittest.main()
