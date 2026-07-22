# Passkey

Dependency-free WebAuthn passkey example for Node.js and modern browsers.

## Run

```bash
npm start
```

Open `http://localhost:8000` (not `127.0.0.1` — WebAuthn binds to the RP ID).

Edit `config.js` if you change host, port, or deploy over HTTPS.

## Flow

Create a passkey (signs you in):

```text
POST /api/register/options
navigator.credentials.create()
POST /api/register/verify   → session cookie
```

Sign in again later:

```text
POST /api/login/options    → allowCredentials: [] (account picker)
navigator.credentials.get()
POST /api/login/verify      → session cookie
```

Session:

```text
GET  /api/session
POST /api/logout
```

The server checks challenge, origin, RP ID, user verification, and (on sign-in)
the ES256 signature, then sets an HttpOnly session cookie. Create and login
verify both start a session. Registered credentials are saved to
`credentials.json` so they survive restarts; challenges and sessions stay in
memory.
