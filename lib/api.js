import config from '../config.js';
import passkey from './passkey.js';

const readBody = async (req) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
};

const cookieValue = (header, name) => {
  if (!header) return '';
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=');
  }
  return '';
};

const SECURE = config.ORIGIN.startsWith('https://') ? '; Secure' : '';

const sessionCookie = (token, maxAge) => {
  const base = `session=${token}; HttpOnly; SameSite=Strict; Path=/`;
  const age = `Max-Age=${maxAge}`;
  return `${base}; ${age}${SECURE}`;
};

const routes = {
  'POST /api/register/options': (body) => passkey.registrationOptions(body),
  'POST /api/register/verify': (body) => passkey.verifyRegistration(body),
  'POST /api/register/enroll/options': () => passkey.enrollOptions(),
  'POST /api/register/enroll': (body) => passkey.enrollCredential(body),
  'POST /api/authenticate/options': () => passkey.authenticationOptions(),
  'POST /api/authenticate/verify': (body) => {
    const result = passkey.verifyAuthentication(body);
    const { token, ...data } = result;
    return {
      ...data,
      headers: {
        'Set-Cookie': sessionCookie(token, config.SESSION_TTL / 1000),
      },
    };
  },
  'GET /api/session': (_body, token) => {
    const user = token ? passkey.getSession(token) : null;
    return { status: user ? 200 : 401, authenticated: Boolean(user), user };
  },
  'POST /api/logout': (_body, token) => {
    if (token) passkey.revokeSession(token);
    return {
      authenticated: false,
      headers: { 'Set-Cookie': sessionCookie('', 0) },
    };
  },
};

const handle = async (req, res) => {
  const path = new URL(req.url || '/', config.ORIGIN).pathname;
  const route = routes[`${req.method} ${path}`];
  if (!route) return false;
  const body = await readBody(req);
  const token = cookieValue(req.headers.cookie, 'session');
  const { status = 200, headers = {}, ...data } = await route(body, token);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    ...headers,
  });
  res.end(JSON.stringify(data));
  return true;
};

const sendError = (res, error) => {
  const expected = error instanceof passkey.ServerError;
  res.writeHead(expected ? error.status : 500, {
    'Content-Type': 'application/json; charset=utf-8',
  });
  res.end(
    JSON.stringify({
      error: expected ? error.message : 'Unexpected server error',
    }),
  );
};

export { handle, sendError };
