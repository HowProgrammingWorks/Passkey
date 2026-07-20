import { readFile } from 'node:fs/promises';
import path from 'node:path';

import config from '../config.js';

const MIME = {
  html: 'text/html; charset=utf-8',
  json: 'application/json; charset=utf-8',
  js: 'application/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  txt: 'text/plain; charset=utf-8',
  ico: 'image/x-icon',
};

const fileCache = new Map();

const getFileContent = async (filePath) => {
  if (fileCache.has(filePath)) return fileCache.get(filePath);
  const content = await readFile(filePath).catch(() => null);
  if (content) fileCache.set(filePath, content);
  return content;
};

const serveFile = async (req, res) => {
  const pathname = new URL(req.url || '/', config.ORIGIN).pathname;
  const requestPath = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.join(config.STATIC_DIR, requestPath.slice(1));
  if (!filePath.startsWith(config.STATIC_DIR)) {
    res.writeHead(404, { 'Content-Type': MIME.html });
    return void res.end('Not found');
  }
  const content = await getFileContent(filePath);
  if (!content) {
    res.writeHead(404, { 'Content-Type': MIME.html });
    return void res.end('Not found');
  }
  const mimeType = path.extname(filePath).slice(1);
  const type = MIME[mimeType] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': type });
  res.end(content);
};

export { serveFile };
