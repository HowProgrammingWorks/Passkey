import { createServer } from 'node:http';

import config from './config.js';
import staticFiles from './lib/static.js';

const server = createServer(async (req, res) => {
  try {
    await staticFiles.serve(req, res);
  } catch (error) {
    console.error(error);
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Unexpected server error');
  }
});

server.listen(config.PORT, config.HOST, () => {
  console.log(`HTTP server listening on http://${config.HOST}:${config.PORT}`);
});
