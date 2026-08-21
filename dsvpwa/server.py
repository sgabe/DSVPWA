import sqlite3
import xml.etree.ElementTree as ET

from http.server import ThreadingHTTPServer


class VulnHTTPServer(ThreadingHTTPServer):
    users = []
    for user in ET.parse('./db/users.xml').findall("user"):
        users.append((
            user.findtext('username'),
            user.findtext('firstname'),
            user.findtext('lastname'),
            user.findtext('email'),
            user.findtext('password'),
            '' # SESSION
        ))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection = sqlite3.connect(
            ':memory:',
            isolation_level=None,
            check_same_thread=False
        )
        self.reset_database()

    def reset_database(self):
        """Restore the deterministic state expected at the start of a lab."""
        self.connection.executescript('''
            DROP TABLE IF EXISTS comments;
            DROP TABLE IF EXISTS users;

            CREATE TABLE users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                firstname TEXT,
                lastname TEXT,
                email TEXT,
                password TEXT,
                session TEXT
            );

            CREATE TABLE comments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                comment TEXT,
                time TEXT
            );
        ''')
        self.connection.executemany('''
            INSERT INTO users(id, username, firstname, lastname, email, password, session)
            VALUES(NULL, ?, ?, ?, ?, ?, ?)''',
            self.users
        )

    def server_close(self):
        try:
            self.connection.close()
        finally:
            super().server_close()
