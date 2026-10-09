"""Install and run an isolated primary-only usage monitor, without touching RADIUS.

Credentials are JSON {api_key, app_key} read from GCP Secret Manager using the
VM service account. Grant that account accessor on only this secret; scope the
Datadog application key to logs_read_data. Credentials stay in root memory.
"""
import argparse
import base64
import json
import logging
import math
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from urllib.request import Request, build_opener

import radius_usage_collector


LOG = logging.getLogger('radius_usage_service')
UNIT_NAME = 'radius-usage-collector.service'
MARKER = '# Managed radius usage monitor; does not control FreeRADIUS.'
SOURCE_FILES = ('radius_usage.py', 'radius_usage_collector.py', 'radius_usage_service.py')


def load_credentials(secret):
    """Fetch without subprocesses, local credential files, redirects or error leaks."""
    try:
        opener = build_opener(radius_usage_collector.NoRedirect())
        request = Request('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
                          headers={'Metadata-Flavor': 'Google'})
        with opener.open(request, timeout=15) as response:
            token = json.loads(response.read(65537))['access_token']
        if not isinstance(token, str) or not token:
            raise ValueError('Malformed service account token')
        request = Request('https://secretmanager.googleapis.com/v1/' + secret + ':access',
                          headers={'Authorization': 'Bearer ' + token})
        with opener.open(request, timeout=30) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('Oversized secret response')
        encoded = json.loads(raw)['payload']['data']
        credentials = json.loads(base64.b64decode(encoded, validate=True))
        if not isinstance(credentials, dict) or not all(
                isinstance(credentials.get(key), str) and credentials[key] for key in ('api_key', 'app_key')):
            raise ValueError('Malformed Datadog credential secret')
        return credentials
    except Exception:
        raise RuntimeError('Usage credential retrieval failed') from None


def validate(args):
    if not re.fullmatch(r'projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+/versions/(?:latest|[0-9]+)', args.secret):
        raise ValueError('Secret must be a complete Secret Manager version resource')
    for value in (args.primary_host, args.collector_id):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', value):
            raise ValueError('Primary host and collector ID must be stable host-like identities')
    if socket.gethostname().split('.')[0] != args.primary_host:
        raise ValueError('Usage monitor is restricted to its configured primary host')
    if not math.isfinite(args.interval) or args.interval <= 0:
        raise ValueError('Interval must be positive')
    if not math.isfinite(args.settle_seconds) or args.settle_seconds < 0:
        raise ValueError('Settle seconds must be nonnegative')
    radius_usage_collector.configured_hosts(args.source_hosts)
    if args.site not in {'datadoghq.com', 'us3.datadoghq.com', 'us5.datadoghq.com',
                         'datadoghq.eu', 'ap1.datadoghq.com', 'ap2.datadoghq.com', 'ddog-gov.com'}:
        raise ValueError('Unsupported Datadog site')
    if args.preview_id is not None and not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', args.preview_id):
        raise ValueError('Preview ID must be a single stable label')
    for key in ('state', 'install_dir', 'source_dir', 'unit_path'):
        value = getattr(args, key, None)
        if value is not None and (not Path(value).is_absolute() or any(c in value for c in '\n\r\0')):
            raise ValueError('Runtime paths must be absolute and single-line')
    if args.command == 'install' and Path(args.unit_path).name != UNIT_NAME:
        raise ValueError('Installer only manages ' + UNIT_NAME)


def unit_quote(value):
    # systemd command parsing is separate from shell parsing; % is a specifier.
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def render_unit(args):
    command = ['/usr/bin/python3', str(Path(args.install_dir) / 'radius_usage_service.py'),
               'run', '--secret', args.secret, '--state', args.state, '--site', args.site,
               '--interval', str(args.interval), '--settle-seconds', str(args.settle_seconds),
               '--collector-id', args.collector_id, '--primary-host', args.primary_host]
    command.extend(['--source-hosts', *args.source_hosts])
    if args.preview_id:
        command.extend(['--preview-id', args.preview_id])
    if args.debug:
        command.append('--debug')
    return '\n'.join([
        MARKER, '[Unit]', 'Description=RADIUS observed usage collector',
        'Wants=network-online.target', 'After=network-online.target', 'StartLimitIntervalSec=0',
        '', '[Service]', 'Type=simple', 'User=root', 'Group=root', 'UMask=0077',
        'ExecStart=' + ' '.join(unit_quote(value) for value in command),
        'Restart=always', 'RestartSec=120', 'TimeoutStopSec=30',
        'NoNewPrivileges=true', 'PrivateTmp=true', 'ProtectHome=true', 'ProtectSystem=strict',
        'ReadWritePaths=' + unit_quote(Path(args.state).parent),
        'ProtectKernelTunables=true', 'ProtectKernelModules=true', 'ProtectControlGroups=true',
        'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX', 'CapabilityBoundingSet=',
        '', '[Install]', 'WantedBy=multi-user.target', ''])


def private_write(path, content, mode):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing to replace a symlink')
    fd, temporary = tempfile.mkstemp(prefix='.usage-install-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            os.fchmod(target.fileno(), mode)
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install(args):
    unit = render_unit(args)
    if args.dry_run:
        print(unit)
        return
    if os.geteuid() != 0:
        raise ValueError('Install requires root')
    source = Path(args.source_dir)
    contents = {name: (source / name).read_bytes() for name in SOURCE_FILES}
    unit_path = Path(args.unit_path)
    if unit_path.is_symlink() or (unit_path.exists() and MARKER not in unit_path.read_text().splitlines()):
        raise ValueError('Refusing to replace an unmanaged unit')
    state = Path(args.state)
    state_parent = state.parent
    install_dir = Path(args.install_dir)
    # Validate both destinations before creating files or changing permissions.
    # In particular, --state /var/lib/checkpoint.json must never chmod /var/lib.
    for directory, names in ((state_parent, {state.name, state.name + '.lock', state.name + '.runner.lock'}),
                             (install_dir, set(SOURCE_FILES) | {'__pycache__'})):
        if directory.is_symlink():
            raise ValueError('Runtime directory must not be a symlink')
        if directory.exists():
            if not directory.is_dir():
                raise ValueError('Runtime path must be a directory')
            for entry in directory.iterdir():
                if entry.name not in names or entry.is_symlink():
                    raise ValueError('Runtime directory must be dedicated to the usage monitor')
                if directory == install_dir and entry.name == '__pycache__' and entry.is_dir():
                    for cached in entry.iterdir():
                        if cached.is_symlink() or not cached.is_file() or not any(
                                re.fullmatch(re.escape(Path(name).stem) + r'\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc', cached.name)
                                for name in SOURCE_FILES):
                            raise ValueError('Runtime directory must be dedicated to the usage monitor')
                elif not entry.is_file():
                    raise ValueError('Runtime directory must be dedicated to the usage monitor')
    for directory, mode in ((install_dir, 0o755), (state_parent, 0o700)):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(mode)
    # Existing checkpoints, including uncertain pending deliveries, are preserved.
    for name, content in contents.items():
        private_write(Path(args.install_dir) / name, content, 0o644)
    private_write(unit_path, unit.encode(), 0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', UNIT_NAME], check=True)
    subprocess.run(['systemctl', 'restart', UNIT_NAME], check=True)
    LOG.info('Installed primary usage monitor with durable checkpoint %s', args.state)


def run(args):
    if os.geteuid() != 0 and not args.dry_run:
        raise ValueError('Permanent monitor requires root for protected credentials and checkpoint')
    credentials = load_credentials(args.secret)
    collector = radius_usage_collector.Collector(
        credentials, args.state, site=args.site, preview_id=args.preview_id,
        dry_run=args.dry_run, heartbeat=True, collector_id=args.collector_id, hosts=args.source_hosts)
    with radius_usage_collector.runner_lock(args.state, args.dry_run):
        # First pass can recover an existing checkpoint; its overlap is selected
        # by Collector rather than discarding or reseeding durable state.
        end = time.time() - args.settle_seconds
        start = end - 600
        while True:
            report = collector.run_once(start, end)
            LOG.info('Usage collection: %s', json.dumps(report, separators=(',', ':')))
            if args.dry_run:
                return
            time.sleep(args.interval)
            start, end = end, time.time() - args.settle_seconds


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('install', 'run'):
        command = commands.add_parser(name)
        command.add_argument('--secret', required=True, help='projects/PROJECT/secrets/NAME/versions/latest')
        command.add_argument('--state', default='/var/lib/radius-usage/checkpoint.json')
        command.add_argument('--site', default='us5.datadoghq.com')
        command.add_argument('--primary-host', default='radius-primary')
        command.add_argument('--collector-id', default='radius-primary')
        command.add_argument('--source-hosts', nargs='+', default=['radius-primary', 'radius-secondary'])
        command.add_argument('--interval', type=float, default=120)
        command.add_argument('--settle-seconds', type=float, default=120)
        command.add_argument('--preview-id')
        command.add_argument('--dry-run', action='store_true')
        command.add_argument('--debug', action='store_true')
        if name == 'install':
            command.add_argument('--source-dir', default=str(Path(__file__).resolve().parent))
            command.add_argument('--install-dir', default='/opt/radius-usage')
            command.add_argument('--unit-path', default='/etc/systemd/system/' + UNIT_NAME)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='%(levelname)s %(message)s')
    try:
        validate(args)
        if args.command == 'install':
            install(args)
        else:
            run(args)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        LOG.error('%s', error)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
