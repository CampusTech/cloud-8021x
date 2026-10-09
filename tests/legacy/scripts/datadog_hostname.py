#!/usr/bin/env python3
"""Persist a single deployment-scoped Datadog identity without rewriting secrets."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile


DNS_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z')
IDENTITY_KEY = re.compile(r'^(?:hostname|host_aliases|"hostname"|"host_aliases"|\'hostname\'|\'host_aliases\')\s*:')
COMMENTED_KEY = re.compile(r'^#\s*(?:hostname|host_aliases)\s*:')


def validate_label(value, field):
    if len(value) > 63 or not DNS_LABEL.fullmatch(value):
        raise ValueError(field + ' must be a lowercase DNS label of at most 63 characters')
    return value


def monitoring_hostname(instance, suffix):
    validate_label(instance, 'instance')
    if suffix:
        validate_label(suffix, 'suffix')
    return validate_label(instance + ('-' + suffix if suffix else ''), 'combined hostname')


def render_identity(source, hostname, alias):
    """Replace all root identity keys, retaining other config and nested keys.

    Datadog's config uses unindented root mapping keys. Consume existing alias
    lists, including YAML's legal unindented list form, to remove old aliases
    that could merge this VM with a different deployment.
    """
    kept = []
    removing = False
    for line in source.splitlines(keepends=True):
        if IDENTITY_KEY.match(line):
            removing = True
            continue
        if COMMENTED_KEY.match(line):
            continue
        if removing:
            if not line.strip() or line.startswith((' ', '\t', '- ', '#')):
                # Retain comments and empty lines, but consume alias values.
                if not line.strip() or line.lstrip().startswith('#'):
                    kept.append(line)
                continue
            removing = False
        kept.append(line)
    remaining = ''.join(kept).rstrip('\r\n')
    prefix = remaining + '\n' if remaining else ''
    return (prefix + 'hostname: ' + json.dumps(hostname) + '\n'
            + 'host_aliases: ' + json.dumps([alias]) + '\n')


def configure(path, instance, project, suffix, dry_run=False):
    hostname = monitoring_hostname(instance, suffix)
    validate_label(project, 'project')
    # This matches the Agent's GCE alias; never add the unscoped VM name.
    alias = instance + '.' + project
    path = Path(path).resolve(strict=True)
    original_stat = path.stat()
    if not stat.S_ISREG(original_stat.st_mode):
        raise ValueError('config must be a regular file')
    source = path.read_text()
    updated = render_identity(source, hostname, alias)
    if source == updated or dry_run:
        return source != updated, hostname
    # A crash cannot leave a partially written config. Keep the protected
    # permissions and original ownership, including when bootstrap runs as root.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.datadog-hostname-', delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), stat.S_IMODE(original_stat.st_mode))
            current_stat = os.fstat(output.fileno())
            if (current_stat.st_uid, current_stat.st_gid) != (original_stat.st_uid, original_stat.st_gid):
                os.fchown(output.fileno(), original_stat.st_uid, original_stat.st_gid)
            output.write(updated)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return True, hostname


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/datadog-agent/datadog.yaml')
    parser.add_argument('--instance', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--suffix', required=True, help='Resolved deployment suffix; empty preserves an existing production hostname')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        changed, hostname = configure(args.config, args.instance, args.project, args.suffix, args.dry_run)
    except (OSError, UnicodeError):
        # Never print configuration content (the file contains the API key).
        parser.error('could not safely read or update Datadog configuration')
    except ValueError as error:
        parser.error(str(error))
    action = 'would update' if args.dry_run and changed else 'updated' if changed else 'unchanged'
    print('Datadog host identity ' + action + ': ' + hostname)


if __name__ == '__main__':
    main()
