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

const saveCredentials = () => {
  fs.writeFileSync(
    config.CREDENTIALS_FILE,
    JSON.stringify([...credentials.values()], null, 2),
  );
};

loadCredentials();

const randomId = () => crypto.randomBytes(32).toString('base64url');

const createChallenge = (data) => {
  const challenge = randomId();
  challenges.set(challenge, {
    ...data,
    expiresAt: Date.now() + config.CHALLENGE_TTL,
  });
  return challenge;
};

const takeChallenge = (challenge, type) => {
  const entry = challenges.get(challenge);
  challenges.delete(challenge);
  if (!entry || entry.type !== type || entry.expiresAt <= Date.now()) {
    throw new ServerError('Invalid or expired challenge');
  }
  return entry;
};

const parseClientData = (encoded, expectedType) => {
  const bytes = Buffer.from(encoded, 'base64url');
  const data = JSON.parse(bytes.toString('utf8'));
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

const parseAuthData = (encoded) => {
  const bytes = Buffer.from(encoded, 'base64url');
  if (bytes.length < 37) throw new ServerError('Invalid authenticator data');
  const expected = crypto.createHash('sha256').update(config.RP_ID).digest();
  if (!bytes.subarray(0, 32).equals(expected)) {
    throw new ServerError('Unexpected RP ID');
  }
  const flags = bytes[32];
  if ((flags & 0x01) === 0) throw new ServerError('User presence required');
  if ((flags & 0x04) === 0) {
    throw new ServerError('User verification required');
  }
  return { bytes, flags };
};

const removeUsername = (username, keepId) => {
  for (const [id, credential] of credentials) {
    if (credential.username === username && id !== keepId) {
      credentials.delete(id);
    }
  }
};

const parsePublicKey = (encoded) => {
  const publicKey = Buffer.from(encoded, 'base64url');
  crypto.createPublicKey({ key: publicKey, format: 'der', type: 'spki' });
  return publicKey.toString('base64url');
};

const verifyAssertion = (record, response, challengeType) => {
  const { bytes: clientDataJSON, challenge } = parseClientData(
    response.clientDataJSON,
    'webauthn.get',
  );
  takeChallenge(challenge, challengeType);
  const authData = parseAuthData(response.authenticatorData);
  if (response.userHandle !== record.userId) {
    throw new ServerError('User mismatch', 401);
  }
  const signed = Buffer.concat([
    authData.bytes,
    crypto.createHash('sha256').update(clientDataJSON).digest(),
  ]);
  const key = crypto.createPublicKey({
    key: Buffer.from(record.publicKey, 'base64url'),
    format: 'der',
    type: 'spki',
  });
  const signature = Buffer.from(response.signature, 'base64url');
  if (!crypto.verify('sha256', signed, key, signature)) {
    throw new ServerError('Invalid signature', 401);
  }
};

const storeCredential = ({ id, username, userId, publicKey }) => {
  removeUsername(username, id);
  credentials.set(id, { id, username, userId, publicKey });
  saveCredentials();
  return { verified: true, user: { username } };
};

const registrationOptions = ({ username }) => {
  if (typeof username !== 'string' || !username.trim()) {
    throw new ServerError('Invalid username');
  }
  username = username.trim();
  let userId = randomId();
  for (const credential of credentials.values()) {
    if (credential.username === username) {
      userId = credential.userId;
      break;
    }
  }
  return {
    challenge: createChallenge({ type: 'registration', username, userId }),
    rp: { id: config.RP_ID, name: config.RP_NAME },
    user: { id: userId, name: username, displayName: username },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    },
    attestation: 'none',
  };
};

const verifyRegistration = ({ id, type, response }) => {
  if (!id || type !== 'public-key') throw new ServerError('Invalid credential');
  const { challenge } = parseClientData(
    response.clientDataJSON,
    'webauthn.create',
  );
  const { username, userId } = takeChallenge(challenge, 'registration');
  const authData = parseAuthData(response.authenticatorData);
  if ((authData.flags & 0x40) === 0) {
    throw new ServerError('Missing attested credential data');
  }
  if (response.publicKeyAlgorithm !== -7) {
    throw new ServerError('Only ES256 is supported');
  }
  return storeCredential({
    id,
    username,
    userId,
    publicKey: parsePublicKey(response.publicKey),
  });
};

const enrollOptions = () => ({
  challenge: createChallenge({ type: 'enroll' }),
  rpId: config.RP_ID,
  userVerification: 'required',
});

const enrollCredential = ({
  id,
  type,
  username,
  userId,
  publicKey,
  response,
}) => {
  if (!id || type !== 'public-key') throw new ServerError('Invalid credential');
  if (typeof username !== 'string' || !username.trim()) {
    throw new ServerError('Invalid username');
  }
  if (typeof userId !== 'string' || !userId) {
    throw new ServerError('Invalid user id');
  }
  username = username.trim();
  const record = {
    id,
    username,
    userId,
    publicKey: parsePublicKey(publicKey),
  };
  verifyAssertion(record, response, 'enroll');
  return storeCredential(record);
};

const authenticationOptions = () => {
  if (credentials.size === 0) {
    throw new ServerError('No passkeys registered yet', 404);
  }
  return {
    challenge: createChallenge({ type: 'authentication' }),
    rpId: config.RP_ID,
    userVerification: 'required',
    allowCredentials: [...credentials.keys()].map((id) => ({
      type: 'public-key',
      id,
    })),
  };
};

const verifyAuthentication = ({ id, type, response }) => {
  if (!id || type !== 'public-key') throw new ServerError('Invalid credential');
  const record = credentials.get(id);
  if (!record) throw new ServerError('Unknown credential', 401);
  verifyAssertion(record, response, 'authentication');
  const token = randomId();
  sessions.set(token, {
    username: record.username,
    expiresAt: Date.now() + config.SESSION_TTL,
  });
  return { verified: true, token, user: { username: record.username } };
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
  enrollOptions,
  enrollCredential,
  authenticationOptions,
  verifyAuthentication,
  getSession,
  revokeSession,
};
