# Damn Simple Vulnerable Python Web Application

**DSVPWA** is a simple web application written in Python and mainly inspired by [DSVW](https://github.com/stamparm/DSVW). It is deliberately vulnerable for educational purposes to demonstrate some of the [OWASP TOP Ten](https://owasp.org/www-project-top-ten/) security risks and other vulnerabilities. It supposed to be used locally in a virtual machine or in a Docker container.

## Features

In comparison to other similar projects, this application also provides very basic *session management* and *HTML templating*. Currently it can be used to demonstrate the following security attacks and vulnerabilities:
+ [Cross-site request forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
+ [Command injection](https://owasp.org/www-community/attacks/Command_Injection)
+ [Deserialization of untrusted data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
+ [Execution after redirect (EAR)](https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR))
+ [Insecure transport](https://owasp.org/www-community/vulnerabilities/Insecure_Transport)
+ [Open redirect](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
+ [Path traversal](https://owasp.org/www-community/attacks/Path_Traversal)
+ [Cross-site scripting (XSS)](https://owasp.org/www-community/attacks/xss)
+ [Session fixation](https://owasp.org/www-community/attacks/Session_fixation)
+ [Session hijacking](https://owasp.org/www-community/attacks/Session_hijacking_attack)
+ [SQL injection](https://owasp.org/www-community/attacks/SQL_Injection)
+ [Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)

## Requirements

The project's goal is to be simple, hence the only requirement is [Python 3.9](https://www.python.org/downloads/). Note that some attacks or vulnerabilities might have additional requirements. However, most of the features should be still available on minimal configurations.

## Usage

### Standalone

You can simply run the standalone application with:

    > python dsvpwa.py

### Docker

You can build and run the application with an interactive shell (`-it`) in a container that is automatically removed (`--rm`) and bind the container's default port to the host (`-p`):

    > docker build -t dsvpwa .
    > docker run --rm -it -p 127.0.0.1:65413:65413 dsvpwa

Note that ports which are not bound to the host (i.e., `-p 65413:65413` instead of `-p 127.0.0.1:65413:65413`) will be accessible from the outside.

## Similar projects

+ [Damn Small Vulnerable Web (DSVW)](https://github.com/stamparm/DSVW)
+ [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)
+ [DVPWA -- Damn Vulnerable Python Web Application](https://github.com/anxolerd/dvpwa)
+ [Extreme Vulnerable Node Application (XVNA)](https://github.com/vegabird/xvna)
+ [Mutillidae II](https://github.com/webpwnized/mutillidae)
+ [WebGoat](https://github.com/WebGoat/WebGoat)

## Disclaimer

This is a vulnerable application and may compromise the security of your system. It is intended to be used for educational purposes only and should not be used with malicious intent. It is supposed to be used in safe, restricted, local environments. Default configuration binds to localhost to minimize the exposure. The author is not responsible for any damage or loss of data after using this software. Use it on your own risk!
