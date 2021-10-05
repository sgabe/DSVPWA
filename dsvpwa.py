#!/usr/bin/env python

import os
import ssl
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
    parser.add_argument('--port', type=int, default=os.getenv('DSVPWA_PORT', 65413),
        help='set the port number to bind to (defaults to 65413)')
    parser.add_argument('--risk', type=int, default=os.getenv('DSVPWA_RISK', 1), choices=range(1,4),
        help='set the risk level in the range 1-3')
    parser.add_argument('--ssl', action='store_true', default=os.getenv('DSVPWA_SSL', 0),
        help='enable encryption (defaults to false)')
    parser.add_argument('--version', action='version',
        version='%(prog)s v{} ({})'.format(BUILD_VER, BUILD_REV))

    args = parser.parse_args()
    proto = 'http' if not args.ssl else 'https'

    try:
        httpd = VulnHTTPServer((args.host, args.port), VulnHTTPRequestHandler)
        httpd.RequestHandlerClass.risk = args.risk

        if args.ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.options &= ~ssl.OP_NO_SSLv3
            ctx.options &= ~ssl.OP_NO_COMPRESSION
            ctx.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE
            ctx.load_cert_chain(certfile='./ssl/cert.pem', keyfile='./ssl/key.pem')
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

        print('[*] Navigate to {}://{}:{} to access DSVPWA'.format(proto, args.host, args.port))
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('[*] Quitting...')
        pass
    except Exception as ex:
        print("[!] Exception occurred ('%s')" % ex)
    finally:
        httpd.server_close()
        os._exit(0)


if __name__ == "__main__":
    main()
