import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));

export default {
  HOST: '127.0.0.1',
  PORT: 8000,
  RP_ID: 'localhost',
  RP_NAME: 'Passkey Example',
  ORIGIN: 'http://localhost:8000',
  STATIC_DIR: path.join(root, 'static'),
  CREDENTIALS_FILE: path.join(root, 'credentials.json'),
  CHALLENGE_TTL: 5 * 60 * 1000,
  SESSION_TTL: 60 * 60 * 1000,
};
