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

const contentType = (filePath) => {
  const dot = filePath.lastIndexOf('.');
  const ext = dot === -1 ? 'html' : filePath.slice(dot + 1);
  return MIME[ext] || 'application/octet-stream';
};

const safeJoin = (base, requestPath) => {
  const cleaned = path.normalize(requestPath).replace(/^(\.\.[/\\])+/, '');
  const full = path.join(base, cleaned);
  const rel = path.relative(config.root, full);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return null;
  return full;
};

const notFound = (res) => {
  res.writeHead(404, { 'Content-Type': MIME.html });
  res.end('Not found');
};

const serveFile = async (res, filePath) => {
  if (!fileCache.has(filePath)) {
    try {
      fileCache.set(filePath, await readFile(filePath));
    } catch (error) {
      if (error?.code === 'ENOENT') {
        notFound(res);
        return;
      }
      throw error;
    }
  }
  res.writeHead(200, { 'Content-Type': contentType(filePath) });
  res.end(fileCache.get(filePath));
};

const serve = async (req, res) => {
  const pathname = (req.url || '/').split('?')[0];
  const requestPath = pathname === '/' ? '/index.html' : pathname;
  const target = safeJoin(config.STATIC_DIR, requestPath);
  if (!target) {
    notFound(res);
    return;
  }
  await serveFile(res, target);
};

export default { serve };
