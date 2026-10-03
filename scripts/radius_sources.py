"""Resolve pinned UniFi console IDs to authenticated RADIUS source addresses.

No packet-provided NAS identity enters discovery. Each node owns a separate
firewall rule and refresh lock; a local expiry guard denies stale discoveries.
"""
import argparse
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

MAX_AGE = 900
CONFIG = Path('/etc/freeradius/3.0/radius-sources.json')
STATE = Path('/var/lib/radius-sources/state.json')
CLIENTS = Path('/etc/freeradius/3.0/clients-discovered.conf')
SECRETS = Path('/run/radius-source-secrets.json')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_json(url, headers, body=None, method=None):
    request = urllib.request.Request(url, headers=headers, method=method,
                                    data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError('discovery response too large')
    return json.loads(data)


def fetch_hosts(api_key, request=http_json):
    hosts, seen, token = [], set(), None
    for _ in range(100):
        query = {'pageSize': '100'}
        if token:
            query['nextToken'] = token
        page = request('https://api.ui.com/v1/hosts?' + urllib.parse.urlencode(query),
                       {'X-API-Key': api_key, 'Accept': 'application/json'})
        if not isinstance(page, dict) or not isinstance(page.get('data'), list):
            raise ValueError('invalid UniFi hosts response')
        hosts.extend(page['data'])
        token = page.get('nextToken')
        if not token:
            return hosts
        if not isinstance(token, str) or token in seen:
            raise ValueError('invalid or repeated UniFi pagination token')
        seen.add(token)
    raise ValueError('UniFi hosts pagination limit exceeded')


def fresh(timestamp, now):
    return (type(timestamp) in (int, float) and math.isfinite(timestamp)
            and 0 <= now - timestamp < MAX_AGE)


def validate_sources(sources):
    networks = []
    for office, ranges in sources.items():
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', office):
            raise ValueError('unsafe RADIUS office name')
        for cidr in ranges:
            network = ipaddress.ip_network(cidr, strict=True)
            if network.version != 4 or network.prefixlen == 0 or network.is_loopback:
                raise ValueError('RADIUS sources must be non-loopback IPv4 CIDRs narrower than /0')
            for other_office, other in networks:
                if other_office != office and network.overlaps(other):
                    raise ValueError('RADIUS source ranges overlap between offices')
            networks.append((office, network))


def discover(clients, hosts, now):
    selected = {}
    result = {}
    for office, config in clients.items():
        identifier = config.get('unifi_host_id')
        if not identifier:
            continue
        if identifier in selected:
            raise ValueError('UniFi host ID belongs to more than one office')
        selected[identifier] = office
        matches = [host for host in hosts if isinstance(host, dict) and host.get('id') == identifier]
        if len(matches) != 1:
            raise ValueError('configured UniFi host is missing or ambiguous')
        host = matches[0]
        # updatedAt is a resource modification timestamp, not a heartbeat.
        # Freshness is measured from this successful authenticated API fetch.
        if host.get('isBlocked') is True:
            raise ValueError('configured UniFi host is blocked')
        addresses = [host.get('ipAddress')]
        # Multi-WAN is version-dependent. Only public, observed IPv4s are used;
        # private WANs behind upstream NAT are not public RADIUS egress addresses.
        for wan in (host.get('reportedState') or {}).get('wans', []):
            addresses.append(wan.get('ipv4'))
        public = set()
        for raw in addresses:
            if not raw:
                continue
            address = ipaddress.ip_address(raw)
            if address.version == 4 and address.is_global and not address.is_multicast:
                public.add(str(address) + '/32')
        if not public:
            raise ValueError('configured UniFi host has no observed public IPv4 address')
        result[office] = sorted(public)
    validate_sources({office: config.get('cidrs', []) + result.get(office, [])
                      for office, config in clients.items()})
    return result


def allowed(clients, state, office, source, now):
    try:
        client = clients[office]
        address = ipaddress.ip_address(source)
        if any(address in ipaddress.ip_network(cidr) for cidr in client.get('cidrs', [])):
            return True
        return bool(client.get('unifi_host_id') and fresh(state.get('updated_at'), now)
                    and state.get('host_ids', {}).get(office) == client['unifi_host_id']
                    and any(address in ipaddress.ip_network(cidr)
                            for cidr in state.get('sources', {}).get(office, [])))
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def render_clients(sources, secrets):
    validate_sources(sources)
    blocks = []
    for office in sorted(sources):
        secret = secrets[office]
        if not isinstance(secret, str) or not re.fullmatch(r'[A-Za-z0-9]{32,128}', secret):
            raise ValueError('invalid per-office RADIUS secret')
        for number, cidr in enumerate(sources[office]):
            blocks.append(f'client discovered-{office}-{number} {{\n'
                          f'    ipaddr = {cidr}\n    secret = {secret}\n'
                          f'    shortname = {office}\n    nastype = other\n}}\n')
    return '\n'.join(blocks)


def atomic_write(path, content, mode=0o640):
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
            temporary = stream.name
            os.fchmod(stream.fileno(), mode)
            # Keep the existing group, including freerad for its private includes.
            if path.exists():
                os.fchown(stream.fileno(), -1, path.stat().st_gid)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def metadata(path):
    request = urllib.request.Request('http://metadata.google.internal/computeMetadata/v1/' + path,
                                     headers={'Metadata-Flavor': 'Google'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=5) as response:
        return response.read(16384).decode()


def update_firewall(project, node, sources):
    if node not in ('radius-primary', 'radius-secondary') or not re.fullmatch(r'[a-z][a-z0-9-]+', project):
        raise ValueError('invalid discovery firewall target')
    token = json.loads(metadata('instance/service-accounts/default/token'))['access_token']
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    url = 'https://compute.googleapis.com/compute/v1/projects/' + project + '/global/firewalls/allow-' + node + '-discovered'
    ranges = sorted({cidr for values in sources.values() for cidr in values})
    desired = {'sourceRanges': ranges or ['192.0.2.1/32'], 'disabled': not bool(ranges)}
    current = http_json(url, headers)
    if sorted(current.get('sourceRanges', [])) == desired['sourceRanges'] and current.get('disabled', False) == desired['disabled']:
        return
    # Only sourceRanges/disabled are patched. Terraform owns ports, network,
    # direction and per-node target tags. No create/delete/project-wide access.
    http_json(url, headers, desired, 'PATCH')
    for _ in range(20):
        current = http_json(url, headers)
        if sorted(current.get('sourceRanges', [])) == desired['sourceRanges'] and current.get('disabled', False) == desired['disabled']:
            return
        time.sleep(1)
    raise RuntimeError('discovery firewall update did not converge')


def reconcile(config, sources, now, *, secrets, client_file=CLIENTS, state_file=STATE,
              run=subprocess.run, firewall=update_firewall, node=None):
    # Static CIDRs already have client entries, so avoid duplicate /32 entries.
    additions = {office: [cidr for cidr in ranges
                         if not any(ipaddress.ip_network(cidr).subnet_of(ipaddress.ip_network(static))
                                    for static in config['clients'][office].get('cidrs', []))]
                 for office, ranges in sources.items()}
    content = render_clients(additions, secrets)
    old = client_file.read_text() if client_file.exists() else ''
    changed = content != old
    if changed:
        atomic_write(client_file, content)
        try:
            run(['freeradius', '-XC'], check=True, capture_output=True, timeout=30)
            run(['systemctl', 'restart', 'freeradius'], check=True, capture_output=True, timeout=45)
        except Exception:
            atomic_write(client_file, old)
            run(['systemctl', 'restart', 'freeradius'], check=False, capture_output=True, timeout=45)
            raise
    # Do not mark new observations fresh until both client config and firewall
    # are ready. A failed cloud update can never prolong old discovery validity.
    firewall(config['project'], node or metadata('instance/name'), sources)
    state = {'updated_at': now, 'sources': sources,
             'host_ids': {office: item['unifi_host_id'] for office, item in config['clients'].items()
                          if item.get('unifi_host_id')}}
    atomic_write(state_file, json.dumps(state), 0o644)
    return changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('refresh', 'check'))
    parser.add_argument('source', nargs='?')
    parser.add_argument('office', nargs='?')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text())
    if args.command == 'check':
        try:
            state = json.loads(STATE.read_text())
        except (OSError, ValueError):
            state = {}
        return 0 if allowed(config['clients'], state, args.office, args.source, time.time()) else 1
    with open('/run/radius-sources.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Secrets live only in /run and are fetched on every boot by systemd.
        credentials = json.loads(SECRETS.read_text())
        now = time.time()
        sources = discover(config['clients'], fetch_hosts(credentials['api_key']), now)
        if args.dry_run:
            print(json.dumps(sources, sort_keys=True))
        else:
            changed = reconcile(config, sources, now, secrets=credentials['offices'])
            print(json.dumps({'event': 'source_discovery_refreshed', 'clients_changed': changed,
                              'office_count': len(sources)}))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        # API exceptions can contain URLs but never print credential/header/body.
        print(json.dumps({'event': 'source_discovery_failed', 'error_type': type(exc).__name__}),
              file=sys.stderr)
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
