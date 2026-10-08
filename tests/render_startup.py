"""Render the actual Terraform template with public test fixtures; no cloud/state access."""
import base64
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def render(enabled=True, smallstep=False, webhook=False, certificate_inventory=False, source_discovery=False):
    block = (ROOT / 'compute.tf').read_text().split('startup_script = templatefile', 1)[1].split('\n  })', 1)[0]
    values = {key: 'test' for key in re.findall(r'^    (\w+)\s*=', block, re.M)}
    for key in values:
        if key.startswith('has_') or key in ('smallstep_enabled', 'acme_webhook_enabled',
                'rewrite_username', 'tls_session_cache', 'vlan_policy_enabled',
                'fleet_certificate_inventory', 'scep_certificate_inventory', 'certificate_inventory_enabled', 'unifi_source_discovery_enabled'):
            values[key] = key == 'tls_session_cache'
    values.update(unifi_source_discovery_enabled=source_discovery, certificate_inventory_enabled=certificate_inventory, vlan_policy_enabled=enabled, radius_trust_mode='okta', tls_max_version='1.2',
                  scep_certificate_inventory=certificate_inventory and webhook,
                  fleet_certificate_inventory=certificate_inventory,
                  tls_session_cache_lifetime=24, radius_clients_json='{}',
                  rewrite_username_separator=' - ', acme_webhook_url='https://127.0.0.1:9444/authorize' if webhook else '',
                  smallstep_enabled=smallstep, acme_webhook_enabled=webhook)
    for name in ('device_policy', 'inventory_policy', 'radius_vlan', 'fleet_certificates', 'radius_identity', 'radius_log', 'radius_sources', 'attested_acme'):
        values[name + '_module_b64'] = base64.b64encode((ROOT / 'scripts' / (name + '.py')).read_bytes()).decode()
    values['windows_certificates_script_b64'] = base64.b64encode((ROOT / 'scripts/windows_certificates.ps1').read_bytes()).decode()
    policy = {'group_vlans': {'staff': 100, 'byod': 200}, 'fallback_vlan': None,
              'vlan_names': {'100': 'Secure', '200': 'Guest "BYOD"'},
              'cache_max_age': 3600, 'certificate_inventory': certificate_inventory, 'certificate_max_age': 86400, 'cache_file': '/etc/freeradius/3.0/device-policy-cache.json'}
    values['vlan_policy_config_b64'] = base64.b64encode(json.dumps(policy if enabled else None).encode()).decode()
    values['radius_sources_config_b64'] = base64.b64encode(b'{"project":"test","clients":{}}').decode()
    values['attested_acme_config_b64'] = base64.b64encode(b'{"issuer_file":"/etc/freeradius/3.0/certs/attested-acme-issuer.pem","provisioner":"wifi-acme"}').decode()
    values['fleet_acme_profile_uuids_b64'] = base64.b64encode(b'[]').decode()
    values['fleet_scep_profile_uuids_b64'] = base64.b64encode(b'null').decode()
    expression = 'templatefile(' + json.dumps(str(ROOT / 'scripts/startup.sh')) + ', local.template_values)'
    with tempfile.TemporaryDirectory() as directory:
        # Embedded modules can exceed console's 64 KiB input-line limit.
        (Path(directory) / 'main.tf.json').write_text(json.dumps({'locals': {'template_values': values}}))
        result = subprocess.run(['terraform', '-chdir=' + directory, 'console'],
                                input=expression, capture_output=True, text=True, check=True)
    # terraform console emits multiline strings as <<EOT heredocs.
    output = result.stdout.strip()
    if output.startswith('<<'):
        lines = output.splitlines()
        output = '\n'.join(lines[1:-1]) + '\n'
    else:
        output = json.loads(output)
    subprocess.run(['bash', '-n'], input=output, text=True, check=True)
    return output


if __name__ == '__main__':
    print(render(), end='')
