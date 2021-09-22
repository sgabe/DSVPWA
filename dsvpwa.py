#!/usr/bin/env python

import os
import argparse

from dsvpwa.server import VulnHTTPServer
from dsvpwa.handlers import VulnHTTPRequestHandler

BUILD_VER = os.getenv('BUILD_VER') or '0.0.1'
BUILD_REV = os.getenv('BUILD_REV') or 'dev'

def main():

    parser = argparse.ArgumentParser(prog='DSVPWA',
        description='Damn Simple Vulnerable Python Web Application')
    parser.add_argument('--host', default='127.0.0.1',
        help='set the IP address to bind to (defaults to 127.0.0.1)')
    parser.add_argument('--port', type=int, default=65413,
        help='set the port number to bind to (defaults to 65413)')
    parser.add_argument('--version', action='version',
        version='%(prog)s v{} ({})'.format(BUILD_VER, BUILD_REV))

    args = parser.parse_args()

    try:
        httpd = VulnHTTPServer((args.host, args.port), VulnHTTPRequestHandler)
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        print("[!] Exception occurred ('%s')" % ex)
    finally:
        httpd.server_close()
        os._exit(0)


if __name__ == "__main__":
    main()
