import os
import re
import time
import secrets
import html
import base64
import pickle
import sqlite3
import subprocess
import urllib.request
import urllib.parse as urlparse


class Attack():
    warning = (
        'This attack vector is unavailable on the current risk level ({}). '
        'Try to increase the value for --risk to enable more dangerous attack '
        'vectors like this.'
    )

    def __init__(self, title, description, route, good_path, evil_path, reference,
                 owasp='', cwe='', objective='', source='', sink='', defense=''):
        self.title = title
        self.description = description
        self.route = route
        self.good_path = good_path
        self.evil_path = evil_path
        self.reference = reference
        self.owasp = owasp
        self.cwe = cwe
        self.objective = objective
        self.source = source
        self.sink = sink
        self.defense = defense

    @staticmethod
    def _example(label, value):
        value = value or ''
        escaped = html.escape(value, quote=True)
        if value.startswith('/') or value.startswith('http://') or value.startswith('https://'):
            return '<a href="{}">{}</a>'.format(escaped, label)
        return '<code>{}</code>'.format(escaped)

    def lesson(self, handler):
        """Render student-facing context without changing the selected behavior."""
        mode = getattr(handler, 'security_mode', 'vulnerable')
        return '''
        <aside class="card mb-4 lesson-card d-none" aria-hidden="true">
            <div class="card-body">
                <p><span class="badge badge-{mode_class}">{mode}</span></p>
                <h2 class="h5">Learning objective</h2>
                <p>{objective}</p>
                <p class="mb-1"><strong>OWASP:</strong> {owasp}</p>
                <p class="mb-1"><strong>CWE:</strong> {cwe}</p>
                <p class="mb-1"><strong>Data flow:</strong> <code>{source}</code> &rarr; <code>{sink}</code></p>
                <details class="mt-3">
                    <summary>Why this is vulnerable</summary>
                    <p class="mt-2">{description}</p>
                </details>
                <details class="mt-2">
                    <summary>Guided examples</summary>
                    <p class="mt-2">Benign: {good}<br>Adversarial: {evil}</p>
                </details>
                <details class="mt-2">
                    <summary>What a defense should change</summary>
                    <p class="mt-2">{defense}</p>
                </details>
                <p class="mt-3 mb-0"><a href="{reference}" target="_blank" rel="noopener">OWASP reference</a></p>
            </div>
        </aside>
        '''.format(
            mode=html.escape(mode.title()),
            mode_class='danger' if mode == 'vulnerable' else 'success',
            objective=html.escape(self.objective),
            owasp=html.escape(self.owasp),
            cwe=html.escape(self.cwe),
            source=html.escape(self.source),
            sink=html.escape(self.sink),
            description=html.escape(self.description),
            defense=html.escape(self.defense),
            good=self._example('open example', self.good_path),
            evil=self._example('open example', self.evil_path),
            reference=html.escape(self.reference, quote=True),
        )

    def execute(self, handler):
        if getattr(handler, 'security_mode', 'vulnerable') == 'secure':
            return self.run_secure(handler)
        return self.run(handler)

    def run_secure(self, handler):
        return '<div class="alert alert-info">A secure comparison has not been implemented for this lesson yet.</div>'

    def run(self):
        pass


class SQLinjection(Attack):
    def run(self, handler):
        params = handler.params
        cursor = handler.server.connection.cursor()

        id = '9999999' if 'id' not in params else params['id'][0]
        try:
            cursor.execute("SELECT id, username, firstname, lastname, email, session FROM users WHERE id=" + id)
        except sqlite3.OperationalError as e:
            return e

        rows = ""
        for row in cursor.fetchall():
            columns = ""
            for column in row:
                columns += "".join("<td>{}</td>".format("-" if column is None else column))
            rows += "".join("<tr>{}</tr>".format(columns))

        content = """
            <table class="table">
                <thead>
                    <th scope="col">ID</th>
                    <th scope="col">Username</th>
                    <th scope="col">First name</th>
                    <th scope="col">Last name</th>
                    <th scope="col">E-mail address</th>
                    <th scope="col">Session</th>
                </thead>
                {}
            </table>
        """.format(rows)

        return content


    def run_secure(self, handler):
        params = handler.params
        cursor = handler.server.connection.cursor()
        raw_id = params.get('id', ['9999999'])[0]
        try:
            user_id = int(raw_id)
        except ValueError:
            return '<div class="alert alert-warning">ID must be an integer.</div>'

        cursor.execute(
            "SELECT id, username, firstname, lastname, email, session FROM users WHERE id = ?",
            [user_id]
        )
        rows = ""
        for row in cursor.fetchall():
            columns = "".join(
                "<td>{}</td>".format(html.escape("-" if column is None else str(column)))
                for column in row
            )
            rows += "<tr>{}</tr>".format(columns)

        return """
            <table class="table">
                <thead>
                    <th scope="col">ID</th><th scope="col">Username</th>
                    <th scope="col">First name</th><th scope="col">Last name</th>
                    <th scope="col">E-mail address</th><th scope="col">Session</th>
                </thead>
                {}
            </table>
        """.format(rows)


class XSSReflected(Attack):
    def run(self, handler):
        params = handler.params

        content = params.get('msg', '')
        if len(content):
            content = content[0]
        else:
            content = 'No messages...'

        return content


    def run_secure(self, handler):
        content = handler.params.get('msg', ['No messages...'])[0]
        return html.escape(content)


class XSSStored(Attack):
    def run(self, handler):
        params = handler.params
        connection = handler.server.connection
        cursor = connection.cursor()

        if 'comment' in params:
            comment = params.get('comment', '')[0]
            cursor.execute('INSERT INTO comments VALUES(NULL, ?, ?)', [comment, time.ctime()])
            connection.commit()
            content = 'Thank you for leaving the comment. Please click <a href=/guestbook?comment=>here</a> to see all comments...'
        else:
            cursor.execute("SELECT id, comment, time FROM comments")
            rows = ""
            for row in cursor.fetchall():
                columns = ""
                for column in row:
                    columns += "".join("<td>{}</td>".format("-" if column is None else column))
                rows += "".join("<tr>{}</tr>".format(columns))

            content = '''
                <div><span>Comment(s):</span></div>
                <table>
                    <thead>
                        <th>id</th>
                        <th>comment</th>
                        <th>time</th>
                    </thead>
                    {}
                </table>'''.format(rows)

        return content


    def run_secure(self, handler):
        params = handler.params
        connection = handler.server.connection
        cursor = connection.cursor()

        if 'comment' in params:
            comment = params.get('comment', '')[0]
            cursor.execute('INSERT INTO comments VALUES(NULL, ?, ?)', [comment, time.ctime()])
            connection.commit()
            return 'Thank you for leaving the comment. Please return to the guestbook to see all comments.'

        cursor.execute("SELECT id, comment, time FROM comments")
        rows = ""
        for row in cursor.fetchall():
            columns = "".join(
                "<td>{}</td>".format(html.escape("-" if column is None else str(column)))
                for column in row
            )
            rows += "<tr>{}</tr>".format(columns)
        return """
            <div><span>Comment(s):</span></div>
            <table>
                <thead><th>id</th><th>comment</th><th>time</th></thead>
                {}
            </table>""".format(rows)


class UnvalidatedRedirect(Attack):
    def run(self, handler):
        params = handler.params

        path = params.get('path', '/')[0]
        content = '''
            <script>
                setTimeout(function() {{
                    window.location.replace('{path}');
                }}, 3000);
            </script>
        '''.format(path=path)

        return content


class ExecutionAfterRedirect(Attack):
    def run(self, handler):
        cookie = handler.cookie

        content = '''
            <ul>
                <li><a href=#>Manage Users</a></li>
                <li><a href=#>Update Database Settings</a></li>
            </ul>
        '''

        if not cookie:
            content += "<script>window.location = '/login';</script>"

        return content


class CommandInjection(Attack):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        domain = 'www.google.com'
        payload = ';ifconfig' if os.name != 'nt' else '&ipconfig'
        payload = urlparse.quote_plus(payload)
        self.evil_path = '{}?domain={}{}'.format(self.route, domain, payload)

    def run(self, handler):
        params = handler.params

        if handler.risk < 3:
            content = self.warning.format(handler.risk)
        else:
            content = 'Try <a href="{}">this</a> or <a href="{}">this</a>...'.format(self.good_path, self.evil_path)
            if 'domain' in params:
                command = 'host' if os.name != 'nt' else 'nslookup'
                domain = params.get('domain', '/')[0]
                output = subprocess.check_output(
                    ' '.join([command, domain]),
                    shell=True,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE
                )
                content = '<pre>{}</pre>'.format(output.decode())

        return content


    def run_secure(self, handler):
        params = handler.params
        if 'domain' not in params:
            return 'Enter a domain name to run the secure comparison.'

        domain = params.get('domain', [''])[0]
        if (not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', domain)
                or domain.startswith('-') or '..' in domain):
            return '<div class="alert alert-warning">Invalid domain name.</div>'

        command = 'host' if os.name != 'nt' else 'nslookup'
        try:
            output = subprocess.check_output(
                [command, domain],
                shell=False,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as ex:
            output = ex.output
        return '<pre>{}</pre>'.format(html.escape(output.decode(errors='replace')))


class UnsafeDeserialization(Attack):

    class RCE:
        def __reduce__(self):
            cmd = ('whoami >> poc.txt')
            return os.system, (cmd,)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        payload = base64.urlsafe_b64encode(pickle.dumps(dict(one=1, two=2, three=3))).decode()
        self.good_path = '/extract?object={}'.format(payload)
        payload = base64.urlsafe_b64encode(pickle.dumps(self.RCE())).decode()
        self.evil_path = '/extract?object={}'.format(payload)

    def run(self, handler):
        params = handler.params

        content = 'Try <a href="{}">this</a> or <a href="{}">this</a>...'.format(self.good_path, self.evil_path)

        if handler.risk < 3:
            content = self.warning.format(handler.risk)
        elif 'object' in params:
            object = params.get('object', '')[0]
            content = str(pickle.loads(base64.urlsafe_b64decode(object)))

        return content


class PathTraversal(Attack):
    def run(self, handler):
        params = handler.params

        try:
            path = params.get('path', ['docs/cursus.txt'])[0]
            if '://' not in path:
                file = open(os.path.abspath(path), 'rb')
            else:
                file = urllib.request.urlopen(path)

            file = html.escape(file.read().decode())
        except:
            file = 'File not found...'

        content = '<pre><code>{}</code></pre>'.format(file)

        return content


    def run_secure(self, handler):
        path = handler.params.get('path', ['docs/cursus.txt'])[0]
        docs_root = os.path.abspath('docs')
        requested = os.path.abspath(path)
        try:
            if os.path.commonpath([docs_root, requested]) != docs_root:
                raise ValueError('requested path escaped the documents directory')
            with open(requested, 'rb') as document:
                value = document.read().decode()
            return '<pre><code>{}</code></pre>'.format(html.escape(value))
        except (OSError, ValueError, UnicodeDecodeError):
            return '<div class="alert alert-warning">Document not available.</div>'


class SessionFixation(Attack):
    def run(self, handler):
        params = handler.params
        cookie = handler.cookie

        if params.keys() & {'session'}:
            session = params.get('session')[0]
            cookie['SESSIONID'] = session

        path = params.get('path', '/')[0]
        content = '''
            <script>
                setTimeout(function() {{
                    window.location = '{path}';
                }}, 3000);
            </script>
        '''.format(path=path)

        return content


    def run_secure(self, handler):
        path = handler.params.get('path', ['/'])[0]
        if not path.startswith('/') or path.startswith('//'):
            path = '/'
        return (
            '<div class="alert alert-success">'
            'The supplied <code>session</code> parameter was ignored. Session identifiers '
            'are generated by the server and rotated after authentication.'
            '</div><p><a href="{}">Continue</a></p>'
        ).format(html.escape(path, quote=True))


class SessionHijacking(Attack):
    def run(self, handler):
        cursor = handler.server.connection.cursor()
        content = 'Please login, <strong>Anonymous</strong>!'

        if 'SESSIONID' in handler.cookie:
            session = handler.cookie['SESSIONID'].value
            cursor.execute("SELECT * FROM users WHERE session = ?", [session])

            user = cursor.fetchone()
            if user:
                content = '''
                <h2>Welcome <strong>{}</strong>!</h2>
                Your first name: <pre>{}</pre>
                Your last name: <pre>{}</pre>
                Your email address: <pre>{}</pre>
                '''.format(user[1], user[2], user[3], user[4])

        return content


class AuthBypass(Attack):
    def run(self, handler):
        params = handler.params
        connection = handler.server.connection
        cursor = connection.cursor()
        session = handler.cookie['SESSIONID'].value

        type = 'empty'
        message = ''
        content = '''
            <div class="alert alert-{type}" role="alert">
                <div class="message">{message}</div>
            </div>
        '''

        if params.keys() == {'username', 'password'}:
            username = re.sub(r"[^\w]", '', params.get('username')[0])
            password = params.get('password')[0]

            if username == 'dsvpwa' and password == 'dsvpwa':
                user = ['dsvpwa', 'Default', 'Default', 'dsvpwa']
            else:
                try:
                    cursor.execute("SELECT * FROM users WHERE username='" +  username + "' AND password='" + password + "'")
                except sqlite3.OperationalError as e:
                    return content.format(type=type, message=e)
                user = cursor.fetchone()

            if user:
                type = 'success'
                message = 'Welcome <strong>{} {}</strong>!'.format(user[2], user[3])
                cursor.execute("UPDATE users SET session = ? WHERE id = ?", (session, user[0]))
                connection.commit()
            else:
                type = 'danger'
                message = 'The username and/or password is incorrect!'

        content = content.format(type=type, message=message)

        return content


    def run_secure(self, handler):
        params = handler.params
        connection = handler.server.connection
        cursor = connection.cursor()
        session = handler.cookie['SESSIONID'].value
        alert_type = 'empty'
        message = ''
        content = """
            <div class="alert alert-{type}" role="alert">
                <div class="message">{message}</div>
            </div>
        """

        if params.keys() == {'username', 'password'}:
            username = params.get('username')[0]
            password = params.get('password')[0]
            cursor.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, password)
            )
            user = cursor.fetchone()
            if user:
                alert_type = 'success'
                message = 'Welcome <strong>{} {}</strong>!'.format(
                    html.escape(str(user[2])), html.escape(str(user[3])))
                # Authentication is a trust-boundary change: rotate the token so
                # a pre-authentication value cannot be fixed by another party.
                session = secrets.token_urlsafe(24)
                handler.cookie['SESSIONID'] = session
                cursor.execute("UPDATE users SET session = ? WHERE id = ?", (session, user[0]))
                connection.commit()
            else:
                alert_type = 'danger'
                message = 'The username and/or password is incorrect!'

        return content.format(type=alert_type, message=message)


class XSRequestForgery(Attack):
    def run(self, handler):
        params = handler.params
        connection = handler.server.connection
        cursor = connection.cursor()
        content = 'Please login, <strong>Anonymous</strong>!'

        if 'SESSIONID' in handler.cookie:
            session = handler.cookie['SESSIONID'].value
            cursor.execute("SELECT * FROM users WHERE session = ?", [session])

            user = cursor.fetchone()
            if user:

                if 'email' in params.keys():
                    email = params.get('email')[0]
                    cursor.execute("UPDATE users SET email = ? WHERE id = ?", (email, user[0]))
                    connection.commit()
                    content = 'Your settings have been updated!'
                else:
                    content = '''
                    <p>Change your profile settings here:</p>
                    <form method="GET" action="/settings">
                        <div class="form-group">
                            <label for="firstname">First name:</label>
                            <input type="text" id="firstname" name="firstname" class="form-control" value="{}">
                        </div>
                        <div class="form-group">
                            <label for="lastname">Last name:</label>
                            <input type="text" id="lastname" name="lastname" class="form-control" value="{}">
                        </div>
                        <div class="form-group">
                            <label for="email">Email address:</label>
                            <input type="text" id="email" name="email" class="form-control" value="{}">
                        </div>
                        <div class="form-group">
                            <button class="btn btn-primary" type="submit">Submit</button>
                        </div>
                    </form>
                    '''.format(user[2], user[3], user[4])

        return content


class Clickjacking(Attack):
    def run_secure(self, handler):
        return self.run(handler)

    def run(self, handler):
        params = handler.params
        connection = handler.server.connection
        cursor = connection.cursor()
        content = 'Please login, <strong>Anonymous</strong>!'

        if 'SESSIONID' in handler.cookie:
            session = handler.cookie['SESSIONID'].value
            cursor.execute("SELECT * FROM users WHERE session = ?", [session])

            user = cursor.fetchone()
            if user:

                if 'delete' in params.keys():
                    cursor.execute("DELETE FROM users WHERE id = ?", [user[0]])
                    connection.commit()
                    content = '''
                    <div class="alert alert-success">
                        Your account has been deleted!
                    </div>
                    '''
                else:
                    content = '''
                    <div class="alert alert-danger">
                        Irreversible and destructive actions!
                    </div>
                    <form method="GET" action="/danger">
                        <div class="form-group">
                            <label>
                                Delete this account
                            </label>
                            <small style="margin-top:-10px" class="form-text text-muted">
                                Once you delete your account, there is no going back. Please be certain.
                            </small>
                            <input type="hidden" name="delete" value="1">
                            <button class="btn btn-danger" type="submit" style="float:right;margin-top:-40px">Delete</button>
                        </div>
                    </form>
                    '''

        return content
