# DSVPWA Learning Guide

This guide is intended for learners who want a structured introduction to web application security. It provides a suggested learning sequence designed to help you build a repeatable way to reason about browser security, trust boundaries, data flow, application controls, and business impact rather than memorize attack payloads.

The application is intentionally vulnerable. Run it only in an isolated local environment. Keep the default host binding to `127.0.0.1`; use a container or disposable virtual machine for risk level 3.

## Recommended learning cycle

Use the same questions for every topic:

1. **Predict** — What should happen in the ordinary case?
2. **Locate** — What data can you control, and where does it cross a trust boundary?
3. **Observe** — What changes when the input or browser context becomes adversarial?
4. **Explain** — Which security assumption was false?
5. **Remediate** — Which control addresses the root cause, and which controls are defense in depth?
6. **Verify** — What evidence shows that the defense changes the behavior?
7. **Impact** — What business process, data asset, user trust, compliance obligation, or operational cost could be affected?

## Running vulnerable and secure versions side by side

Open two terminals or use two containers:

```text
python dsvpwa.py --port 65413
python dsvpwa.py --port 65414 --secure
```

The two ports are also useful when discussing browser origins: the port is part of an origin, so these two instances are different origins even though they use the same host.

Start each lesson with the lesson card collapsed and make your own prediction about the behavior. Use the **Show lesson** control in the footer when you want to compare your reasoning with the supplied learning objective, source, sink, examples, and defense guidance.

The application intentionally keeps its student-facing interactions on **GET**, including state-changing examples. This is a learning simplification that makes requests easy to reproduce from the address bar and browser history. Treat it as a cross-cutting design observation: sensitive values and state-changing actions should not generally be encoded as GET requests.

When a secure comparison exists, repeat the same request against both ports and compare the response body, cookies, status, and security headers. Some lessons intentionally do not implement a complete secure counterpart; in those cases, identify what control would be needed instead of assuming that a partial browser defense solves the root cause.

Reset the in-memory application state from the front page between exercises when necessary, especially after stored XSS and account-deletion exercises.

## Suggested learning sequence

### 1. Same-origin policy (SOP)

Begin with the browser security model before studying individual attacks.

An origin is defined by the combination of **scheme, host, and port**. Compare the vulnerable and secure DSVPWA instances and note that `127.0.0.1:65413` and `127.0.0.1:65414` are different origins.

Focus on three questions:

- When may one origin read data from another origin?
- Which cross-origin actions may still be sent or embedded even when the response cannot be read?
- Why is SOP a browser isolation boundary rather than an authorization mechanism?

DSVPWA does not provide a dedicated SOP attack lesson. Use this topic as the browser foundation for XSS, CSRF, and clickjacking. In particular, remember that SOP does not by itself prove that a cross-origin request was intended by the user, and it does not by itself prevent another site from attempting to frame a page.

### 2. Web application basics (HTTP)

Before modifying requests, identify the parts of an ordinary HTTP interaction:

- method and path;
- query parameters;
- request headers;
- cookies;
- response status;
- response headers;
- response body.

Use a few normal DSVPWA pages and follow one value from the address bar into the request and back into the response. Inspect the `Set-Cookie`, `Cookie`, `Content-Type`, Content Security Policy, and framing-related headers when present.

HTTP requests are independent, so web applications commonly use a session identifier to associate multiple requests with the same user. In DSVPWA, follow the session identifier from the login response into the browser cookie and then into later requests. Treat the session identifier as a bearer credential: possession of a valid identifier may be enough for the server to associate a request with that session.

Use **Home / session fixation** and **Profile / session hijacking** as the practical session-handling exercises for this topic.

For session fixation, ask:

- Can an attacker choose or learn a session identifier before authentication?
- Does the identifier remain the same after the user authenticates?
- What changes in secure mode when the application rotates the session identifier?

For session hijacking, ask:

- What happens when another client presents a valid session identifier?
- Which security decision is the server making based on possession of that identifier?
- Which controls reduce the chance that a browser exposes the identifier, and which controls actually invalidate or replace it?

Inspect the secure-mode cookie attributes such as `HttpOnly` and `SameSite`, but keep their roles separate from session rotation. Browser cookie attributes can reduce some ways a session identifier is exposed or sent; rotating the identifier after authentication addresses fixation.

The goal is to understand both the normal HTTP/session mechanism and the security consequence of treating a session identifier as proof of an existing authenticated session. Later topics such as XSS and CSRF build on this model.

### 3. Cross-site scripting (XSS)

Use **Message / reflected XSS** first, then **Guestbook / stored XSS**.

For reflected XSS, trace:

```text
query parameter -> HTML response -> browser HTML/JavaScript interpretation
```

Ask whether the supplied value is intended to be data or browser program text. Compare the vulnerable response with secure-mode HTML output encoding and then inspect Content Security Policy as a defense-in-depth control.

For stored XSS, separate two events:

1. the application stores a value in the database;
2. a later response renders that value into HTML.

The database can use a parameterized query correctly while the later HTML output is still unsafe. This is why SQL injection defenses do not automatically prevent XSS.

### 4. Cross-site request forgery (CSRF)

Use **Settings / CSRF**.

The central question is not whether the user is authenticated. It is whether the authenticated user intended the state-changing request.

Trace the relationship between:

```text
cross-site request -> automatically attached session credential -> state change
```

Relate this lesson back to SOP: browser origin isolation does not by itself prevent a site from causing certain cross-origin requests to be sent.

The current lesson does not provide a complete secure CSRF counterexample. In secure mode, inspect the session cookie attributes as observable defense in depth, but distinguish them from a dedicated request-intent control such as an anti-CSRF token.

### 5. UI redressing (Clickjacking)

Use **Danger / clickjacking**.

The vulnerable page contains a destructive account action. The security question is whether the user understands which interface is receiving the click.

The application content itself is unchanged in secure mode, so inspect the response headers instead. Compare the vulnerable response with:

```text
X-Frame-Options: DENY
Content-Security-Policy: ... frame-ancestors 'none'
```

Connect this lesson to SOP and CSRF:

- SOP controls some cross-origin reading;
- CSRF concerns unintended authenticated requests;
- clickjacking concerns deceptive presentation and user interaction.

They are related browser-security problems, but they are not interchangeable.

### 6. SQL injection (SQLi)

Use **Users / SQL injection**.

Identify the vulnerable data flow:

```text
id parameter -> SQL string concatenation -> SQLite parser
```

The problem is not the presence of a particular quote or operator. The problem is that untrusted data becomes part of SQL grammar.

Compare the vulnerable implementation with secure mode, which validates the identifier as an integer and supplies it separately to a parameterized query. Explain why this preserves the distinction between data and SQL syntax.

### 7. Man in the Middle (MitM)

DSVPWA does not define a dedicated MitM attack class, so do not treat another application lesson as if it were MitM.

Use this topic to reason about the **transport trust boundary**. If your lab setup enables the application's TLS option, compare HTTP and HTTPS behavior and identify what TLS is intended to protect while data travels between browser and server.

Be able to distinguish:

- application-layer vulnerabilities from transport-layer protection;
- confidentiality from integrity;
- encryption from server authentication;
- a valid TLS connection from a secure web application.

TLS can protect traffic against an on-path observer or modifier when certificate validation and the surrounding setup are correct. It does not repair XSS, CSRF, SQL injection, or other application logic flaws.

### 8. OS command injection (RCE)

Use **Diagnostics / command injection** only at risk level 3 inside a disposable container or virtual machine.

Trace:

```text
domain parameter -> command construction -> operating-system shell
```

The vulnerable implementation combines requester-controlled input with a command and enables shell interpretation. Secure mode validates the domain, passes the command and argument as separate values, and disables shell parsing.

Compare this with SQL injection. In both cases the general problem is the same:

```text
untrusted data + executable grammar + missing separation = injection
```

Only the interpreter changes.

### 9. Python code injection (RCE)

Use **Extract / unsafe deserialization** only at risk level 3 in an isolated environment.

DSVPWA's current Python-side RCE lesson is unsafe `pickle` deserialization rather than direct `eval()` or `exec()` code injection. Keep that distinction explicit.

Trace:

```text
object parameter -> Base64 decoding -> pickle.loads() -> Python object reconstruction
```

The security failure is trusting an attacker-controlled serialized object and passing it to a reconstruction mechanism that can invoke powerful Python behavior.

Use this lesson to connect Python-side RCE with the previous injection topics while also recognizing the difference: unsafe deserialization is not simply string concatenation into Python source code. The safer design is to accept a data-only representation with an explicitly validated structure instead of reconstructing arbitrary Python objects from untrusted input.

## Additional DSVPWA lessons

The application contains useful lessons beyond the suggested sequence. Use them as extensions after the corresponding foundations are clear:

- **Login / authentication bypass** — authentication logic and SQL injection;
- **Documents / path traversal** — attacker-controlled resource names and filesystem boundaries;
- **Admin / execution after redirect** — authorization must occur before protected content is produced;
- **Redirect / unvalidated redirect** — untrusted navigation targets.

These are valuable follow-up exercises, but they do not need to interrupt the nine-topic sequence above.

## Recording your findings

For each topic, keep a short lab record:

| Field | Evidence to record |
| --- | --- |
| Source/context | Requester-controlled input or browser/transport context |
| Sink/boundary | Interpreter, sensitive operation, or security boundary |
| Observation | Request/response or browser evidence showing changed behavior |
| Root cause | One or two sentences explaining the failed assumption |
| Remediation | Root-cause control plus optional defense-in-depth controls |
| Business impact | One concrete effect on data, users, operations, or compliance |

Prioritize a correct explanation over finding additional payloads. A working payload demonstrates behavior; the explanation demonstrates understanding.

## Self-guided exercise pattern

For each DSVPWA-backed lesson:

1. Send an ordinary request and predict the result.
2. Identify the requester-controlled value or browser security context.
3. Predict the interpreter, sensitive operation, or trust boundary involved.
4. Reveal the lesson card and compare it with your prediction.
5. Change one relevant input or context and observe the effect.
6. Explain the result before looking at the defense.
7. When available, repeat the request against secure mode and inspect the changed code, cookie attributes, or response headers.
8. Record one limitation of the defense and one concrete business impact.

If you cannot explain a result in your own words, return to the source, sink, browser boundary, and normal HTTP behavior before trying another payload.

## OWASP mapping note

DSVPWA contains concrete weaknesses and attack techniques, while the OWASP Top 10 contains broad risk categories that may cover many CWEs. A lab therefore does not need a one-to-one correspondence with a Top 10 item. Use the lesson metadata to distinguish a broad risk category from a specific weakness.

The suggested sequence above is organized around a progression of web security concepts rather than OWASP category order.
