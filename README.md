# Passkey

Dependency-free WebAuthn passkey example for Node.js and modern browsers.

## Run

```bash
npm start
```

Open `http://localhost:8000` (not `127.0.0.1` — WebAuthn binds to the RP ID).

Edit `config.js` if you change host, port, or deploy over HTTPS.

## Flow

Registration:

```text
POST /api/register/options
navigator.credentials.create()
POST /api/register/verify
```

Re-register a browser passkey onto the server (public key is kept in
`localStorage` after the first create):

```text
POST /api/register/enroll/options
navigator.credentials.get()
POST /api/register/enroll
```

Authentication:

```text
POST /api/authenticate/options
navigator.credentials.get()
POST /api/authenticate/verify
```

The server checks challenge, origin, RP ID, user verification, and the ES256
signature, then sets an HttpOnly session cookie. Registered credentials are
saved to `credentials.json` so they survive restarts; challenges and sessions
stay in memory. WebAuthn never exposes the public key during `get()`, so enroll
needs a local copy from an earlier `create()` in this browser.
