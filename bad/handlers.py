import os
import sys
import dsvpwa
import string
import random
import mimetypes
import posixpath
import subprocess
import http.cookies
import dsvpwa.attacks
import urllib.parse as urlparse
import xml.etree.ElementTree as ET

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler


class VulnRequestHandler():
    def __init__(self):
        self.content_type = 'text/plain'
        self.content = 'Bad Request'
        self.status_code = HTTPStatus.BAD_REQUEST

    def get_content(self):
        if self.status_code == HTTPStatus.OK:
            return self.content.read()
        return self.content

    def get_status_code(self):
        return self.status_code

    def get_content_type(self):
        return self.content_type


class TemplateHandler(VulnRequestHandler):
    attacks = []
    for attack in ET.parse('./db/attacks.xml').findall('attack'):
        instance = getattr(dsvpwa.attacks, attack.findtext('class'))(
            title = attack.findtext('title'),
            description = attack.findtext('description'),
            route = attack.findtext('route'),
            good_path = attack.findtext('good_path'),
            evil_path = attack.findtext('evil_path'),
            reference = attack.findtext('reference')
        )
        attacks.append(instance)

    def __init__(self, handler):
        self.handler = handler
        self.content_type = 'text/html'

    def get_navigation(self):
        navigation = ''

        for attack in self.attacks:
            navigation += '''
                <li class="nav-item">
                    <a class="nav-link" href="{path}">{title}</a>
                </li>
            '''.format(path=attack.route, title=attack.title)

        return navigation

    def get_version(self):
        ver = os.getenv('BUILD_VER', dsvpwa.__version__)
        rev = os.getenv('BUILD_REV', 'N/A')
        return 'v{} ({})'.format(ver, rev)

    def get_content(self):
        title = 'Front page'
        content = ''
        version = self.get_version()
        navigation = self.get_navigation()

        for attack in self.attacks:
            if self.handler.path == attack.route:
                title = attack.title
                content = attack.run(self.handler)
                break

        return self.content.read().format(
            project = dsvpwa.__project__,
            url = dsvpwa.__url__,
            author = dsvpwa.__author__,
            version = version,
            title = title,
            navigation = navigation,
            content = content
        )

    def find(self, route):
        try:
            self.content = open('templates/{}'.format(route['template']))
            self.status_code = HTTPStatus.OK
            return True
        except:
            self.content = 'File not found'
            self.status_code = HTTPStatus.NOT_FOUND
            return False


class StaticHandler(VulnRequestHandler):
    extensions_map = _encodings_map_default = {
        '.gz': 'application/gzip',
        '.Z': 'application/octet-stream',
        '.bz2': 'application/x-bzip2',
        '.xz': 'application/x-xz',
    }

    def find(self, path):
        path = 'static/svg/bug-fill.svg' if path == '/favicon.ico' else path
        ext = os.path.splitext(path)[1]
        try:
            if ext in ('.jpg', '.jpeg', '.png', '.woff', '.woff2', '.ttf', '.ico'):
                self.content = open('./{}'.format(path), 'rb')
            else:
                self.content = open('./{}'.format(path), 'r')
            self.content_type = self.guess_type(path)
            self.status_code = HTTPStatus.OK
            return True
        except:
            self.content = 'File not found'
            self.status_code = HTTPStatus.NOT_FOUND
            return False

    def guess_type(self, path):
        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        guess, _ = mimetypes.guess_type(path)
        if guess:
            return guess
        return 'application/octet-stream'


class VulnHTTPRequestHandler(BaseHTTPRequestHandler):
    cookie = http.cookies.SimpleCookie()

    routes = {'/' : {'template' : 'index.html'}}
    for attack in ET.parse('./db/attacks.xml').findall('attack'):
        routes[attack.findtext('route')] = {
            'template' : attack.findtext('template')
        }

    def __init__(self, *args, **kwargs):
        self.directory = os.fspath(os.getcwd())
        super().__init__(*args, **kwargs)

    def log_request(self, code='-', size='-'):
        if isinstance(code, HTTPStatus):
            code = code.value
        sys.stdout.write('[i] %s - %s - "%s" %s %s\n' % (
            self.address_string(),
            self.log_date_time_string(),
            self.requestline,
            str(code),
            str(size)
        ))

    def log_error(self, format, *args):
        sys.stderr.write('[-] %s - %s - %s\n' % (
            self.address_string(),
            self.log_date_time_string(),
            format%args
        ))

    def log_message(self, format, *args):
        sys.stdout.write('[*] %s\n' % (self.address_string(), format%args))

    def do_HEAD(self):
        return

    def do_BDR(self):
        if self.risk < 3:
            self.send_response(HTTPStatus.BAD_REQUEST)
            content = dsvpwa.attacks.Attack.warning.format(self.risk).encode()
        else:
            self.send_response(HTTPStatus.OK)
            content = subprocess.check_output(
                self.path[1:],
                shell=True,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE
            )

        self.send_header('Content-type', 'text/plain')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(content)
        self.wfile.flush()

    def do_GET(self):
        self.params = urlparse.parse_qs(urlparse.urlparse(self.path).query)
        self.path = self.path.split('?', 1)[0]
        self.cookie.load(self.headers.get('Cookie', ''))

        if not self.cookie and '/login' == self.path:
            token = ''.join(random.sample(string.ascii_letters + string.digits, 20))
            self.cookie.load('SESSIONID={}'.format(token))

        ext = os.path.splitext(self.path)[1]
        if (ext == '' or ext == '.html') and (self.path in self.routes):
            handler = TemplateHandler(self)
            handler.find(self.routes[self.path])
        else:
            handler = StaticHandler()
            handler.find(self.path)

        try:
            code = handler.get_status_code()
            content = handler.get_content()
        except Exception as ex:
            content = str(ex)
            code = HTTPStatus.INTERNAL_SERVER_ERROR

        if code == HTTPStatus.OK:
            self.send_response(code)
            self.send_header('Content-type', handler.get_content_type())
        else:
            self.send_error(code, content)
            return None

        if type(content) != bytes:
            body = content.encode('UTF-8', 'replace')
        else:
            body = content

        for morsel in self.cookie.values():
            morsel['path'] = '/'
            self.send_header('Set-Cookie', morsel.OutputString())

        self.send_header('Connection', 'close')
        self.send_header('X-XSS-Protection', '0')
        self.send_header('Content-Security-Policy', "default-src * 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
