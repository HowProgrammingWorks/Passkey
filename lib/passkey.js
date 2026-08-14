import crypto from 'node:crypto';
import fs from 'node:fs';

import config from '../config.js';

class ServerError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const credentials = new Map();
const challenges = new Map();
const sessions = new Map();

const loadCredentials = () => {
  try {
    const raw = fs.readFileSync(config.CREDENTIALS_FILE, 'utf8');
    const list = JSON.parse(raw);
    for (const item of list) credentials.set(item.id, item);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
};

const persistCredentials = () => {
  const list = [...credentials.values()];
  const data = JSON.stringify(list, null, 2);
  fs.writeFileSync(config.CREDENTIALS_FILE, data);
};

loadCredentials();

const randomToken = () => {
  const bytes = crypto.randomBytes(32);
  return bytes.toString('base64url');
};

const sha256 = (data) => {
  const hash = crypto.createHash('sha256');
  return hash.update(data).digest();
};

const fromBase64url = (value) => Buffer.from(value, 'base64url');

const issueChallenge = (payload) => {
  const challenge = randomToken();
  const expiresAt = Date.now() + config.CHALLENGE_TTL;
  challenges.set(challenge, { ...payload, expiresAt });
  return challenge;
};

const consumeChallenge = (challenge, expectedType) => {
  const entry = challenges.get(challenge);
  challenges.delete(challenge);
  const wrongType = entry?.type !== expectedType;
  const expired = entry?.expiresAt <= Date.now();
  if (!entry || wrongType || expired) {
    throw new ServerError('Invalid or expired challenge');
  }
  return entry;
};

const readClientData = (encoded, expectedType) => {
  const bytes = fromBase64url(encoded);
  const text = bytes.toString('utf8');
  const data = JSON.parse(text);
  if (data.type !== expectedType) {
    throw new ServerError('Unexpected ceremony type');
  }
  if (data.origin !== config.ORIGIN) {
    throw new ServerError('Unexpected origin');
  }
  if (typeof data.challenge !== 'string') {
    throw new ServerError('Missing challenge');
  }
  return { bytes, challenge: data.challenge };
};

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

const readAuthenticatorData = (encoded) => {
  const bytes = fromBase64url(encoded);
  if (bytes.length < 37) throw new ServerError('Invalid authenticator data');
  const expected = sha256(config.RP_ID);
  const rpIdHash = bytes.subarray(0, 32);
  if (!rpIdHash.equals(expected)) {
    throw new ServerError('Unexpected RP ID');
  }
  const flags = bytes[32];
  if ((flags & FLAG_UP) === 0) {
    throw new ServerError('User presence required');
  }
  if ((flags & FLAG_UV) === 0) {
    throw new ServerError('User verification required');
  }
  return { bytes, flags };
};

const normalizeSpki = (encoded) => {
  const publicKey = fromBase64url(encoded);
  crypto.createPublicKey({ key: publicKey, format: 'der', type: 'spki' });
  return publicKey.toString('base64url');
};

const assertPublicKeyCredential = ({ id, type }) => {
  if (!id || type !== 'public-key') {
    throw new ServerError('Invalid credential');
  }
};

const userIdForUsername = (username) => {
  for (const credential of credentials.values()) {
    if (credential.username === username) return credential.userId;
  }
  return randomToken();
};

const replaceUsernameCredentials = (username, keepId) => {
  for (const [id, credential] of credentials) {
    if (credential.username === username && id !== keepId) {
      credentials.delete(id);
    }
  }
};

const createSession = (username) => {
  const token = randomToken();
  const expiresAt = Date.now() + config.SESSION_TTL;
  sessions.set(token, { username, expiresAt });
  return token;
};

const ES256 = -7;

const registrationOptions = ({ username }) => {
  if (typeof username !== 'string' || !username.trim()) {
    throw new ServerError('Invalid username');
  }
  username = username.trim();
  const userId = userIdForUsername(username);
  const challenge = issueChallenge({ type: 'registration', username, userId });
  return {
    challenge,
    rp: { id: config.RP_ID, name: config.RP_NAME },
    user: { id: userId, name: username, displayName: username },
    pubKeyCredParams: [{ type: 'public-key', alg: ES256 }],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    },
    attestation: 'none',
  };
};

const verifyRegistration = ({ id, type, response }) => {
  assertPublicKeyCredential({ id, type });
  const { challenge } = readClientData(
    response.clientDataJSON,
    'webauthn.create',
  );
  const { username, userId } = consumeChallenge(challenge, 'registration');
  const authData = readAuthenticatorData(response.authenticatorData);
  if ((authData.flags & FLAG_AT) === 0) {
    throw new ServerError('Missing attested credential data');
  }
  if (response.publicKeyAlgorithm !== ES256) {
    throw new ServerError('Only ES256 is supported');
  }
  const publicKey = normalizeSpki(response.publicKey);
  const record = { id, username, userId, publicKey };
  replaceUsernameCredentials(username, id);
  credentials.set(id, record);
  persistCredentials();
  const token = createSession(username);
  return { verified: true, token, user: { username } };
};

const authenticationOptions = () => {
  if (credentials.size === 0) {
    throw new ServerError('No passkeys registered yet', 404);
  }
  const challenge = issueChallenge({ type: 'authentication' });
  return {
    challenge,
    rpId: config.RP_ID,
    userVerification: 'required',
    allowCredentials: [],
  };
};

const verifyAuthentication = ({ id, type, response }) => {
  assertPublicKeyCredential({ id, type });
  const record = credentials.get(id);
  if (!record) throw new ServerError('Unknown credential', 401);

  const { bytes: clientDataJSON, challenge } = readClientData(
    response.clientDataJSON,
    'webauthn.get',
  );
  consumeChallenge(challenge, 'authentication');
  const authData = readAuthenticatorData(response.authenticatorData);

  if (response.userHandle !== record.userId) {
    throw new ServerError('User mismatch', 401);
  }

  const clientHash = sha256(clientDataJSON);
  const signed = Buffer.concat([authData.bytes, clientHash]);
  const publicKey = fromBase64url(record.publicKey);
  const key = crypto.createPublicKey({
    key: publicKey,
    format: 'der',
    type: 'spki',
  });
  const signature = fromBase64url(response.signature);
  if (!crypto.verify('sha256', signed, key, signature)) {
    throw new ServerError('Invalid signature', 401);
  }

  const username = record.username;
  const token = createSession(username);
  return { verified: true, token, user: { username } };
};

const getSession = (token) => {
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { username: session.username };
};

const revokeSession = (token) => sessions.delete(token);

export default {
  ServerError,
  registrationOptions,
  verifyRegistration,
  authenticationOptions,
  verifyAuthentication,
  getSession,
  revokeSession,
};
