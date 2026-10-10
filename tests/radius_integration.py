"""Run Go-rendered EAP-TLS, VLAN, accounting and JSON identity gates on Debian 13.

Requires an explicitly prepared, labeled disposable FreeRADIUS container and
C8021X_NATIVE_BUNDLE pointing to its verified current package inputs. No cloud
calls, published host ports, or production secrets are used. The --native flag
is retained for existing documented commands; native execution is the default.
"""
import argparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', help='Prepared labeled disposable Debian 13 test container')
    parser.add_argument('--native', action='store_true',
                        help='Compatibility flag; native execution is always used')
    parser.add_argument('--native-mode', default='test',
                        choices=['test', 'sources', 'full', 'legacy', 'attested', 'zero',
                                 'outage', 'replay', 'replay-duplicate', 'permissions',
                                 'sqltls', 'ipv6', 'ports', 'termination'],
                        help='Native fixture gate; see patches/freeradius/README.md for preparation')
    args = parser.parse_args()
    from native_radius_integration import run_native
    run_native(args.container, args.native_mode)


if __name__ == '__main__':
    main()
