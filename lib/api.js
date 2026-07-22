import config from '../config.js';
import passkey from './passkey.js';

const readBody = async (req) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
};

const parseCookies = (cookie = '') => {
  if (!cookie) return {};
  const values = [];
  const items = cookie.split(';');
  for (const item of items) {
    const [key, ...rest] = item.split('=');
    if (!key?.trim()) continue;
    values.push([key.trim(), rest.join('=').trim()]);
  }
  return Object.fromEntries(values);
};

const SECURE = config.ORIGIN.startsWith('https://') ? '; Secure' : '';

const sessionCookie = (token, maxAge = 0) => {
  const age = token ? config.SESSION_TTL / 1000 : maxAge;
  const base = `session=${token}; HttpOnly; SameSite=Strict; Path=/`;
  return `${base}; Max-Age=${age}${SECURE}`;
};

const routes = {
  'POST /api/register/options': (body) => passkey.registrationOptions(body),
  'POST /api/register/verify': (body) => passkey.verifyRegistration(body),
  'POST /api/login/options': () => passkey.authenticationOptions(),
  'POST /api/login/verify': (body) => passkey.verifyAuthentication(body),
  'GET /api/session': (_body, token) => {
    const user = token ? passkey.getSession(token) : null;
    const status = user ? 200 : 401;
    const authenticated = Boolean(user);
    return { status, authenticated, user };
  },
  'POST /api/logout': (_body, token) => {
    if (token) passkey.revokeSession(token);
    return { authenticated: false, token: '' };
  },
};

const handle = async (req, res) => {
  const path = new URL(req.url || '/', config.ORIGIN).pathname;
  const route = routes[`${req.method} ${path}`];
  if (!route) return false;
  const body = await readBody(req);
  const token = parseCookies(req.headers.cookie).session || '';
  const result = await route(body, token);
  const { status = 200, token: sessionToken, ...data } = result;
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
  };
  if (sessionToken !== undefined) {
    headers['Set-Cookie'] = sessionCookie(sessionToken);
  }
  res.writeHead(status, headers);
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
