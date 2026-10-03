"""Collect managed Apple identity certificates using authenticated Fleet MDM results.

A refresh does bounded work without waiting for a device. State is private and
must survive refreshes: deleting it discards the outstanding-command budget.
Only MDM's response UUID links certificates to hosts; certificate subjects and
serial numbers are never used as identity. HTTPS and Fleet API authorization
are required; RADIUS must independently validate the presented TLS chain.
"""
import base64
from collections import Counter
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

APPLE_PLATFORMS = frozenset(('darwin', 'macos', 'ios', 'ipados'))
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError('missing result/enrollment timestamp')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timestamp must contain timezone')
    return parsed.timestamp()


def _enrolled(host):
    return str((host.get('mdm') or {}).get('enrollment_status', '')).startswith('On')


def _save(path, state):
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
            temporary = stream.name
            os.fchmod(stream.fileno(), 0o600)
            json.dump(state, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _requester(base, token):
    url = urllib.parse.urlsplit(base)
    if url.scheme != 'https' or not url.netloc or url.username or url.password:
        raise ValueError('Fleet base URL must use HTTPS without embedded credentials')
    # Do not forward bearer credentials to a redirect destination.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect())

    def request(method, path, body=None):
        encoded = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base.rstrip('/') + path, data=encoded, method=method,
                                     headers={'Authorization': 'Bearer ' + token,
                                              'Content-Type': 'application/json'})
        with opener.open(req, timeout=30) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError('Fleet response exceeds size limit')
        return json.loads(data)
    return request


def _trusted(der, ca_file):
    """OpenSSL checks chain, client purpose, and validity before readiness is claimed."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der).encode()
        checked = subprocess.run(['openssl', 'verify', '-purpose', 'sslclient',
                                  '-CAfile', str(ca_file), '-no-CApath', '-no-CAstore'],
                                 input=pem, capture_output=True, timeout=10, check=False)
        if checked.returncode != 0:
            return None
        expiry = subprocess.run(['openssl', 'x509', '-noout', '-enddate'], input=pem,
                                capture_output=True, timeout=10, check=True).stdout.decode()
        return ssl.cert_time_to_seconds(expiry.strip().split('=', 1)[1])
    except (ValueError, IndexError, OSError, subprocess.SubprocessError):
        return None


def _observation(row, command, host_uuid, enrolled_at, now, max_age, ca_file):
    if (row.get('host_uuid') != host_uuid or row.get('command_uuid') != command['uuid']
            or row.get('request_type') != 'CertificateList'
            or row.get('status') != 'Acknowledged'):
        raise ValueError('result does not match requested command')
    observed_at = _timestamp(row.get('updated_at'))
    if not max(command['created_at'], enrolled_at, now - max_age) <= observed_at <= now:
        raise ValueError('result timestamp outside command/enrollment/freshness window')
    payload = plistlib.loads(base64.b64decode(row['result'], validate=True))
    if (not isinstance(payload, dict) or payload.get('CommandUUID') != command['uuid']
            or not any(payload.get(key) == host_uuid for key in ('UDID', 'EnrollmentID'))
            or any(payload.get(key) not in (None, '', host_uuid) for key in ('UDID', 'EnrollmentID'))
            or payload.get('Status') != 'Acknowledged'
            or not isinstance(payload.get('CertificateList'), list)):
        raise ValueError('result plist does not match command and device')
    fingerprints = set()
    expires_at = {}
    for cert in payload['CertificateList']:
        if not isinstance(cert, dict):
            raise ValueError('invalid certificate list entry')
        if cert.get('IsIdentity') is not True:
            continue
        der = cert.get('Data')
        if not isinstance(der, bytes) or not der:
            raise ValueError('missing DER data for identity')
        expiry = _trusted(der, ca_file) if ca_file else None
        if ca_file is None or (expiry is not None and expiry > now):
            fingerprint = hashlib.sha256(der).hexdigest()
            fingerprints.add(fingerprint)
            if expiry is not None:
                expires_at[fingerprint] = expiry
    observation = {'fingerprints': sorted(fingerprints), 'observed_at': observed_at,
                   'trust_verified': ca_file is not None}
    if ca_file:
        observation['expires_at'] = expires_at
    return observation


def refresh(base, token, hosts, state_path, now=None, *, cadence=3600, max_age=86400,
            pending_ttl=3600, batch_size=100, max_batches=1, request=None, ca_file=None):
    """Return UUID -> fingerprints/observed_at after one nonblocking collection pass.

    ``request(method,path,body=None)`` is the injectable authenticated API boundary.
    Fetches each eligible host detail to bind state to last_mdm_enrolled_at. A
    pending command gets at most one concurrent retry after pending_ttl; unresolved
    retries remain tracked so offline hosts cannot accumulate an unbounded queue.
    One process must own state_path (the bulk-cache caller already uses flock).
    """
    now = time.time() if now is None else now
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
               and v > 0 for v in (now, cadence, max_age, pending_ttl, batch_size, max_batches)):
        raise ValueError('positive finite collector limits required')
    if not isinstance(batch_size, int) or not isinstance(max_batches, int):
        raise ValueError('batch limits must be integers')
    request = request or _requester(base, token)
    try:
        state = json.loads(Path(state_path).read_text())
        if state.get('version') != 1:
            raise ValueError('unsupported Fleet certificate state version')
    except FileNotFoundError:
        state = {'version': 1, 'hosts': {}, 'commands': []}
    source = base.rstrip('/')
    if state.get('source') != source:
        state = {'version': 1, 'hosts': {}, 'commands': [], 'source': source}
    trust = hashlib.sha256(Path(ca_file).read_bytes()).hexdigest() if ca_file else None
    if state.get('trust') != trust:
        for cached in state['hosts'].values():
            cached.pop('observation', None)
    state['trust'] = trust
    counts = Counter(h.get('uuid') for h in hosts)
    current = {}
    for host in hosts:
        uid = host.get('uuid')
        if (not isinstance(uid, str) or not uid or counts[uid] != 1
                or host.get('platform') not in APPLE_PLATFORMS or not _enrolled(host)):
            continue
        detail = request('GET', '/api/v1/fleet/hosts/' + str(int(host['id']))).get('host')
        if (not isinstance(detail, dict) or detail.get('id') != host['id']
                or detail.get('uuid') != uid or not _enrolled(detail)):
            continue
        try:
            enrolled_at = _timestamp(detail.get('last_mdm_enrolled_at'))
        except (ValueError, TypeError):
            continue
        if enrolled_at > now:
            continue
        binding = [host['id'], enrolled_at, detail.get('last_enrolled_at')]
        cached = state['hosts'].get(uid, {})
        if cached.get('binding') != binding:
            cached = {'binding': binding, 'last_attempt': 0}
        current[uid] = {**cached, 'platform': host['platform']}
    state['hosts'] = current
    pending = []
    for command in state['commands']:
        command['hosts'] = {uid: binding for uid, binding in command['hosts'].items()
                            if uid in current and binding == current[uid]['binding']}
        if not command['hosts']:
            continue
        try:
            response = request('GET', '/api/v1/fleet/commands/results?' + urllib.parse.urlencode(
                {'command_uuid': command['uuid']}))
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            error.close()
            # A reserved enqueue may have failed before Fleet stored the command.
            # The authenticated API confirms it is absent; retry on normal cadence.
            continue
        rows = response.get('results', [])
        if not isinstance(rows, list):
            raise ValueError('Fleet command results must be a list')
        row_counts = Counter(r.get('host_uuid') for r in rows if isinstance(r, dict))
        for row in rows:
            if not isinstance(row, dict):
                continue
            uid = row.get('host_uuid')
            if uid not in command['hosts'] or row_counts[uid] != 1:
                continue
            if (row.get('command_uuid') != command['uuid']
                    or row.get('request_type') != 'CertificateList'):
                continue
            if row.get('status') in ('Acknowledged', 'Error', 'CommandFormatError'):
                # Terminal failures cannot authorize certificates, but free retry slots.
                del command['hosts'][uid]
                try:
                    observation = _observation(row, command, uid, current[uid]['binding'][1],
                                               now, max_age, ca_file)
                    previous = current[uid].get('observation', {})
                    if observation['observed_at'] >= previous.get('observed_at', 0):
                        current[uid]['observation'] = observation
                except (ValueError, TypeError, KeyError, plistlib.InvalidFileException):
                    pass
        if command['hosts']:
            pending.append(command)
    state['commands'] = pending
    pending_by_host = Counter(uid for command in pending for uid in command['hosts'])
    due = [uid for uid, cached in current.items()
           if pending_by_host[uid] < 2
           and now - cached['last_attempt'] >= (pending_ttl if pending_by_host[uid] else cadence)
           and now - cached.get('observation', {}).get('observed_at', 0) >= cadence]
    due.sort(key=lambda uid: (current[uid]['last_attempt'], uid))
    for _ in range(max_batches):
        if not due:
            break
        platform = current[due[0]]['platform']
        batch = [uid for uid in due if current[uid]['platform'] == platform][:batch_size]
        submitted_uuid = str(uuid.uuid4())
        payload = base64.b64encode(plistlib.dumps(
            {'CommandUUID': submitted_uuid,
             'Command': {'RequestType': 'CertificateList', 'ManagedOnly': True}})).decode()
        if any(c['uuid'] == submitted_uuid for c in state['commands']):
            raise ValueError('duplicate locally generated command UUID')
        state['commands'].append({'uuid': submitted_uuid, 'created_at': now,
                                  'hosts': {uid: current[uid]['binding'] for uid in batch}})
        for uid in batch:
            current[uid]['last_attempt'] = now
            due.remove(uid)
        # Reserve the command before POST: a timeout or APNs error can happen AFTER
        # Fleet has queued it. Retaining its UUID avoids an unbounded offline queue.
        _save(state_path, state)
        result = request('POST', '/api/v1/fleet/commands/run',
                         {'command': payload, 'host_uuids': batch})
        if (result.get('command_uuid') != submitted_uuid
                or result.get('request_type') != 'CertificateList'):
            raise ValueError('Fleet returned invalid command identity/type')
    observations = {}
    for uid, cached in current.items():
        observation = cached.get('observation')
        if observation and 0 <= now - observation['observed_at'] <= max_age:
            if observation.get('trust_verified'):
                observation['fingerprints'] = [fp for fp in observation['fingerprints']
                    if observation.get('expires_at', {}).get(fp, 0) > now]
            observations[uid] = observation
        else:
            cached.pop('observation', None)
    _save(state_path, state)
    return observations


def readiness(hosts, observations, now=None, max_age=86400):
    """Read-only report; trusted identities mean CA chain and validity were checked."""
    now = time.time() if now is None else now
    counts = Counter(h.get('uuid') for h in hosts)
    owners = Counter(fp for obs in observations.values() for fp in set(obs['fingerprints']))
    rows = []
    for host in hosts:
        uid = host.get('uuid')
        observation = observations.get(uid)
        if not uid or counts[uid] != 1:
            reason = 'ambiguous_host_identity'
        elif host.get('platform') not in APPLE_PLATFORMS:
            reason = 'unsupported_platform'
        elif not _enrolled(host):
            reason = 'not_enrolled'
        elif not observation:
            reason = 'no_certificate_observation'
        elif not 0 <= now - observation['observed_at'] <= max_age:
            reason = 'stale_certificate_observation'
        elif not observation['fingerprints']:
            reason = 'no_managed_identity'
        elif any(owners[fp] != 1 for fp in observation['fingerprints']):
            reason = 'ambiguous_certificate_identity'
        elif not observation.get('trust_verified'):
            reason = 'certificate_observed_trust_unverified'
        elif not any(observation.get('expires_at', {}).get(fp, 0) > now
                     for fp in observation['fingerprints']):
            reason = 'expired_certificate_identity'
        else:
            reason = 'ready'
        rows.append({'id': host.get('id'), 'uuid': uid, 'reason': reason})
    ready_count = sum(r['reason'] == 'ready' for r in rows)
    return {'ready': bool(rows) and ready_count == len(rows), 'ready_count': ready_count,
            'generated_at': now, 'max_age': max_age, 'total': len(rows), 'hosts': rows}
