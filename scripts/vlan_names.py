"""Read-only controller VLAN names, isolated from RADIUS authorization.

The scheduled collector writes one atomic snapshot. Packet processing only reads
that snapshot and selects the original signed VLAN in the authenticated office.
"""
import fcntl
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, HTTPRedirectHandler, build_opener

CONFIG_FILE = Path('/etc/freeradius/3.0/vlan-name-sources.json')
CACHE_FILE = Path('/etc/freeradius/3.0/vlan-name-cache.json')
MAX_AGE = 86400  # Display-only last-known-good labels survive short API outages.
MAX_RESPONSE = 8 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_json(url, headers):
    try:
        with build_opener(NoRedirect()).open(Request(url, headers=headers), timeout=20) as response:
            body = response.read(MAX_RESPONSE + 1)
    except HTTPError as exc:
        exc.close()
        raise
    if len(body) > MAX_RESPONSE:
        raise ValueError('controller response too large')
    return json.loads(body)


def source_identity(source):
    """Canonical pinned IDs also prevent reading a previous controller's cache."""
    if not isinstance(source, dict):
        raise ValueError('invalid VLAN name source')
    result = {key: source[key] for key in ('unifi_host_id', 'unifi_site_id', 'meraki_network_id')
              if source.get(key) is not None}
    if any(not isinstance(value, str) or not value or value != value.strip() or len(value) > 255
           for value in result.values()):
        raise ValueError('invalid controller identifier')
    if bool(result.get('unifi_host_id')) == bool(result.get('meraki_network_id')):
        raise ValueError('exactly one VLAN name provider is required')
    if 'unifi_site_id' in result and 'unifi_host_id' not in result:
        raise ValueError('UniFi site requires a console')
    return result


def valid_name(value):
    return (isinstance(value, str) and 0 < len(value) <= 128 and value == value.strip()
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def names_from_rows(rows):
    names, conflicts = {}, set()
    for vlan, name in rows:
        if type(vlan) is int:
            vlan = str(vlan)
        if not isinstance(vlan, str) or not re.fullmatch(r'[1-9][0-9]{0,3}', vlan) or int(vlan) > 4094:
            continue
        if not valid_name(name):
            continue
        if vlan in names and names[vlan] != name:
            conflicts.add(vlan)
        names[vlan] = name
    return {vlan: name for vlan, name in names.items() if vlan not in conflicts}


def unifi_pages(url, headers, request):
    result, offset, total, seen = [], 0, None, set()
    for _ in range(100):
        page = request(url + '?' + urlencode({'offset': offset, 'limit': 200}), headers)
        if not isinstance(page, dict) or not isinstance(page.get('data'), list):
            raise ValueError('invalid UniFi inventory page')
        data = page['data']
        if (type(page.get('offset')) is not int or page['offset'] != offset or
                type(page.get('count')) is not int or page['count'] != len(data) or
                type(page.get('totalCount')) is not int or page['totalCount'] < 0):
            raise ValueError('invalid UniFi inventory pagination')
        if total is None:
            total = page['totalCount']
        if total != page['totalCount'] or offset + len(data) > total:
            raise ValueError('UniFi inventory changed during pagination')
        for item in data:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str) or item['id'] in seen:
                raise ValueError('missing or repeated UniFi inventory ID')
            seen.add(item['id'])
        result.extend(data)
        offset += len(data)
        if offset == total:
            return result
        if not data:
            raise ValueError('incomplete UniFi inventory')
    raise ValueError('UniFi pagination limit exceeded')


def fetch_unifi(source, key, request=http_json):
    source = source_identity(source)
    base = ('https://api.ui.com/v1/connector/consoles/' + quote(source['unifi_host_id'], safe='') +
            '/proxy/network/integration/v1/sites')
    headers = {'X-API-Key': key, 'Accept': 'application/json'}
    sites = unifi_pages(base, headers, request)
    site = source.get('unifi_site_id')
    if site:
        if sum(item['id'] == site for item in sites) != 1:
            raise ValueError('pinned UniFi site missing or ambiguous')
    elif len(sites) == 1:
        site = sites[0]['id']
    else:
        raise ValueError('pin unifi_site_id for a console with multiple sites')
    networks = unifi_pages(base + '/' + quote(site, safe='') + '/networks', headers, request)
    if any('vlanId' not in item or 'name' not in item for item in networks):
        raise ValueError('incomplete UniFi network inventory')
    return names_from_rows((item['vlanId'], item['name']) for item in networks)


def fetch_meraki(source, key, request=http_json):
    source = source_identity(source)
    base = 'https://api.meraki.com/api/v1/networks/' + quote(source['meraki_network_id'], safe='')
    headers = {'Authorization': 'Bearer ' + key, 'Accept': 'application/json'}
    rows, available = [], False
    # MR-only networks may expose named VLAN profiles without an MX appliance.
    # An SSID's name is never a VLAN name. 403/429/5xx retain the old snapshot.
    for endpoint in ('/appliance/vlans', '/vlanProfiles'):
        try:
            data = request(base + endpoint, headers)
        except HTTPError as exc:
            exc.close()
            if exc.code == 404:
                continue
            raise
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            raise ValueError('invalid Meraki VLAN inventory')
        available = True
        for item in data:
            if endpoint == '/appliance/vlans':
                if 'id' not in item or 'name' not in item:
                    raise ValueError('incomplete Meraki appliance VLAN')
                rows.append((item['id'], item['name']))
            else:
                names = item.get('vlanNames')
                if not isinstance(names, list) or any(not isinstance(n, dict) or
                        'vlanId' not in n or 'name' not in n for n in names):
                    raise ValueError('incomplete Meraki named VLAN profile')
                rows.extend((name['vlanId'], name['name']) for name in names)
    if not available:
        raise ValueError('network exposes no supported VLAN inventory')
    return names_from_rows(rows)


def fetch_source(source, credentials):
    provider = 'unifi' if source.get('unifi_host_id') else 'meraki'
    key = credentials.get(provider)
    if not isinstance(key, str) or not key:
        raise ValueError('controller credentials unavailable')
    return (fetch_unifi if provider == 'unifi' else fetch_meraki)(source, key)


def refresh(sources, credentials, cache_file=CACHE_FILE, now=None, fetch=fetch_source):
    now = time.time() if now is None else now
    cache_file = Path(cache_file)
    with open(str(cache_file) + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            old = json.loads(cache_file.read_text()).get('locations', {})
            if not isinstance(old, dict):
                old = {}
        except (OSError, ValueError, AttributeError):
            old = {}
        result, failures = {}, 0
        for office, raw in sources.items():
            source = source_identity(raw)
            try:
                names = fetch(source, credentials)
                result[office] = {'source': source, 'updated_at': now, 'names': names}
            except (OSError, ValueError, TypeError, KeyError) as exc:
                failures += 1
                if isinstance(old.get(office), dict) and old[office].get('source') == source:
                    result[office] = old[office]
                # Never log credentials, URLs or exception bodies.
                reason = 'HTTP ' + str(exc.code) if isinstance(exc, HTTPError) else type(exc).__name__
                print('VLAN name refresh failed for office ' + office + ': ' + reason, file=sys.stderr)
        with tempfile.NamedTemporaryFile(mode='w', dir=cache_file.parent, delete=False) as stream:
            temporary = stream.name
            try:
                os.fchmod(stream.fileno(), 0o644)
                json.dump({'locations': result}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            except Exception:
                os.unlink(temporary)
                raise
        try:
            os.replace(temporary, cache_file)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return failures


def lookup(sources, office, vlan, cache_file=None, now=None):
    if vlan is None:
        return ''
    try:
        source = source_identity(sources[office])
        entry = json.loads(Path(CACHE_FILE if cache_file is None else cache_file).read_text())['locations'][office]
        updated = entry['updated_at']
        now = time.time() if now is None else now
        if (entry['source'] != source or type(updated) not in (int, float) or
                not math.isfinite(updated) or not 0 <= now - updated < MAX_AGE):
            return ''
        name = entry['names'].get(str(vlan))
        return name if valid_name(name) else ''
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return ''


def cached_name(office, vlan):
    try:
        return lookup(json.loads(CONFIG_FILE.read_text()), office, vlan)
    except (OSError, ValueError, TypeError, AttributeError):
        return ''


def main():
    sources = json.loads(CONFIG_FILE.read_text())
    credentials = {}
    try:
        credentials['unifi'] = next(line.split('=', 1)[1].strip() for line in
            Path('/etc/freeradius/3.0/unifi-credentials.conf').read_text().splitlines()
            if line.startswith('UNIFI_API_KEY='))
    except (OSError, StopIteration):
        pass
    try:
        credentials['meraki'] = json.loads(Path('/etc/freeradius/3.0/meraki-credentials.json').read_text())['api_key']
    except (OSError, ValueError, TypeError, KeyError):
        pass
    return 1 if refresh(sources, credentials) else 0


if __name__ == '__main__':
    sys.exit(main())
