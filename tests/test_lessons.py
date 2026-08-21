import http.client
import threading
import unittest
import urllib.parse

from dsvpwa.handlers import VulnHTTPRequestHandler
from dsvpwa.server import VulnHTTPServer


class VulnerableHandler(VulnHTTPRequestHandler):
    risk = 3
    security_mode = 'vulnerable'
    secure_transport = False


class SecureHandler(VulnHTTPRequestHandler):
    risk = 3
    security_mode = 'secure'
    secure_transport = False


class RunningServer:
    def __init__(self, handler):
        self.server = VulnHTTPServer(('127.0.0.1', 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read().decode('utf-8', 'replace')
        result = response.status, dict(response.getheaders()), data
        connection.close()
        return result


class LessonContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vulnerable = RunningServer(VulnerableHandler)
        cls.secure = RunningServer(SecureHandler)

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.close()
        cls.secure.close()

    def setUp(self):
        self.vulnerable.server.reset_database()
        self.secure.server.reset_database()

    def test_learning_context_is_part_of_each_lesson(self):
        status, _, body = self.vulnerable.request('GET', '/users')
        self.assertEqual(status, 200)
        self.assertIn('Learning objective', body)
        self.assertIn('A05:2025 Injection', body)
        self.assertIn('CWE-89', body)
        self.assertIn('id query parameter', body)


    def test_lesson_cards_are_present_but_hidden_by_default(self):
        status, _, body = self.vulnerable.request('GET', '/users?id=2')

        self.assertEqual(status, 200)
        self.assertIn('Learning objective', body)
        self.assertIn('lesson-card d-none', body)
        self.assertIn('aria-hidden="true"', body)
        self.assertIn('id="lesson-card-toggle"', body)
        footer_start = body.index('<footer class="footer">')
        toggle = body.index('id="lesson-card-toggle"')
        footer_end = body.index('</footer>', footer_start)
        self.assertLess(footer_start, toggle)
        self.assertLess(toggle, footer_end)
        self.assertIn('<td>guest</td>', body)

        status, _, javascript = self.vulnerable.request('GET', '/static/js/custom.js')
        self.assertEqual(status, 200)
        self.assertIn('dsvpwa.lessonCardsVisible', javascript)
        self.assertIn("button.textContent = visible ? 'Hide lesson' : 'Show lesson'", javascript)

    def test_generic_file_handler_does_not_duplicate_path_traversal_lesson(self):
        status, _, _ = self.vulnerable.request('GET', '/db/users.xml')
        self.assertEqual(status, 404)
        status, _, body = self.vulnerable.request('GET', '/docs?path=docs/../db/users.xml')
        self.assertEqual(status, 200)
        self.assertIn('&lt;users&gt;', body)

    def test_sql_injection_is_preserved_but_secure_mode_rejects_it(self):
        payload = urllib.parse.quote('1 OR 1=1')
        _, _, vulnerable = self.vulnerable.request('GET', '/users?id=' + payload)
        _, _, secure = self.secure.request('GET', '/users?id=' + payload)
        self.assertIn('<td>guest</td>', vulnerable)
        self.assertIn('<td>loella</td>', vulnerable)
        self.assertIn('ID must be an integer', secure)
        self.assertNotIn('<td>guest</td>', secure)

    def test_reflected_xss_is_preserved_but_secure_mode_encodes_output(self):
        value = '<script>alert(1)</script>'
        payload = urllib.parse.quote(value)
        _, _, vulnerable = self.vulnerable.request('GET', '/post?msg=' + payload)
        _, _, secure = self.secure.request('GET', '/post?msg=' + payload)
        self.assertIn(value, vulnerable)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', secure)

    def test_stored_xss_state_can_be_reset(self):
        query = urllib.parse.urlencode({'comment': '<b>stored</b>'})
        status, _, _ = self.vulnerable.request('GET', '/guestbook?' + query)
        self.assertEqual(status, 200)
        _, _, guestbook = self.vulnerable.request('GET', '/guestbook')
        self.assertIn('<b>stored</b>', guestbook)

        status, reset_headers, _ = self.vulnerable.request('GET', '/__lab/reset')
        self.assertEqual(status, 303)
        self.assertEqual(reset_headers.get('Location'), '/')
        _, _, guestbook = self.vulnerable.request('GET', '/guestbook')
        self.assertNotIn('<b>stored</b>', guestbook)

    def test_authentication_injection_has_a_secure_counterexample(self):
        attack = urllib.parse.urlencode({
            'username': 'guest',
            'password': "' OR '1'='1'--",
        })
        _, _, vulnerable = self.vulnerable.request('GET', '/login?' + attack)
        _, _, secure = self.secure.request('GET', '/login?' + attack)
        self.assertIn('Welcome <strong>', vulnerable)
        self.assertIn('incorrect', secure)

    def test_session_fixation_and_browser_defenses_are_observable(self):
        _, vulnerable_headers, _ = self.vulnerable.request(
            'GET', '/home?session=known-value')
        _, secure_headers, secure_body = self.secure.request(
            'GET', '/home?session=known-value')

        self.assertIn('SESSIONID=known-value', vulnerable_headers.get('Set-Cookie', ''))
        self.assertNotIn('SESSIONID=known-value', secure_headers.get('Set-Cookie', ''))
        self.assertIn('supplied <code>session</code> parameter was ignored', secure_body)
        self.assertEqual(secure_headers.get('X-Frame-Options'), 'DENY')
        self.assertIn("frame-ancestors 'none'", secure_headers.get('Content-Security-Policy', ''))

    def test_secure_login_cookie_uses_defensive_attributes(self):
        _, headers, _ = self.secure.request('GET', '/login')
        cookie = headers.get('Set-Cookie', '')
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)


if __name__ == '__main__':
    unittest.main()
