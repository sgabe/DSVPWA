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

    connection = sqlite3.connect(
        'file::memory:?cache=shared',
        uri=True,
        isolation_level=None,
        check_same_thread=False
    )

    connection.execute('''
        CREATE TABLE users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            firstname TEXT,
            lastname TEXT,
            email TEXT,
            password TEXT,
            session TEXT
        )''')

    connection.execute('''
        CREATE TABLE comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comment TEXT,
            time TEXT
        )''')

    connection.executemany('''
        INSERT INTO users(id, username, firstname, lastname, email, password, session) VALUES(NULL, ?, ?, ?, ?, ?, ?)''',
        users)
