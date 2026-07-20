import { createServer } from 'node:http';

import config from './config.js';
import { handle, sendError } from './lib/api.js';
import { serveFile } from './lib/static.js';

const server = createServer(async (req, res) => {
  try {
    if (await handle(req, res)) return;
    await serveFile(req, res);
  } catch (error) {
    console.error(error);
    sendError(res, error);
  }
});

server.listen(config.PORT, config.HOST, () => {
  console.log(`Passkey server listening on ${config.ORIGIN}`);
});
