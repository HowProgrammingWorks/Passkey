import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));

export default {
  root,
  STATIC_DIR: path.join(root, 'static'),
  HOST: '127.0.0.1',
  PORT: 8000,
};
