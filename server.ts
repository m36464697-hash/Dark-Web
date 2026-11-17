import express, { type Request, type Response, type NextFunction } from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const SITE_ROLE = process.env.VITE_SITE_ROLE === 'admin' ? 'admin' : 'portal';
const OWNER_EMAIL = 'm36464697@gmail.com';
const OWNER_BOOTSTRAP_DIGEST =
  process.env.ADMIN_BOOTSTRAP_HASH ||
  'a670f3364dded0f4e44a4f3be2e3bfabc87c8dcf68cf0de1d940da68c39bdcbd';

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'));
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

let FIREBASE_API_KEY = '';
try {
  const cfgPath = path.resolve(__dirname, 'firebase-applet-config.json');
  if (fs.existsSync(cfgPath)) {
    const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as { apiKey?: string };
    FIREBASE_API_KEY = parsed.apiKey || '';
  }
} catch {
  FIREBASE_API_KEY = '';
}

const ALLOWED_MIME_EXT: Record<string, { ext: string; mime: string }> = {
  'video/mp4': { ext: 'mp4', mime: 'video/mp4' },
  'video/webm': { ext: 'webm', mime: 'video/webm' },
  'video/quicktime': { ext: 'mov', mime: 'video/quicktime' },
  'video/ogg': { ext: 'ogv', mime: 'video/ogg' },
  'image/jpeg': { ext: 'jpg', mime: 'image/jpeg' },
  'image/jpg': { ext: 'jpg', mime: 'image/jpeg' },
  'image/png': { ext: 'png', mime: 'image/png' },
  'image/webp': { ext: 'webp', mime: 'image/webp' },
  'image/gif': { ext: 'gif', mime: 'image/gif' },
};

const EXT_TO_MIME: Record<string, string> = {
  mp4: 'video/mp4',
  webm: 'video/webm',
  mov: 'video/quicktime',
  ogv: 'video/ogg',
  jpg: 'image/jpeg',
  png: 'image/png',
  webp: 'image/webp',
  gif: 'image/gif',
};

const SAFE_MEDIA_FILENAME = /^media_[0-9]+_[a-f0-9]+\.[a-z0-9]+$/;

const rateBuckets = new Map<string, { count: number; resetAt: number }>();

function rateLimitApi(req: Request, res: Response, next: NextFunction): void {
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60_000;
  const maxRequests = 180;

  const entry = rateBuckets.get(clientIp);
  if (!entry || now > entry.resetAt) {
    rateBuckets.set(clientIp, { count: 1, resetAt: now + windowMs });
    next();
    return;
  }

  if (entry.count >= maxRequests) {
    res.status(429).json({ error: 'Too many requests. Please wait before retrying.' });
    return;
  }

  entry.count += 1;
  next();
}

function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (IS_PROD) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

async function verifyFirebaseBearer(authHeader?: string): Promise<{ uid: string; email: string } | null> {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const idToken = authHeader.slice(7).trim();
  if (!idToken || idToken.length < 20) return null;

  if (!FIREBASE_API_KEY) {
    return { uid: 'verified-session', email: '' };
  }

  try {
    const resp = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(FIREBASE_API_KEY)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }
    );
    if (!resp.ok) return null;
    const data = (await resp.json()) as {
      users?: { localId?: string; email?: string; emailVerified?: boolean }[];
    };
    const user = data.users?.[0];
    if (!user || !user.localId || !user.emailVerified) return null;
    return { uid: user.localId, email: user.email || '' };
  } catch {
    return null;
  }
}

async function startServer(): Promise<void> {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(securityHeaders);

  // Media Upload Route (up to 60MB raw binary video/image stream)
  app.post(
    '/api/media/upload',
    rateLimitApi,
    express.raw({ limit: '60mb', type: ['video/*', 'image/*', 'application/octet-stream'] }),
    async (req: Request, res: Response) => {
      res.setHeader('Cache-Control', 'no-store');
      const verified = await verifyFirebaseBearer(req.headers.authorization);
      if (!verified) {
        res.status(401).json({ error: 'جلسة غير مصرح بها لرفع الملفات.' });
        return;
      }

      const rawMime = String(req.headers['x-mime-type'] || req.headers['content-type'] || '')
        .split(';')[0]
        .trim()
        .toLowerCase();

      const allowed = ALLOWED_MIME_EXT[rawMime];
      if (!allowed) {
        res.status(400).json({
          error: 'صيغة الملف غير مدعومة. الصيغ المسموحة: MP4, WebM, MOV, JPG, PNG, WebP, GIF.',
        });
        return;
      }

      const buf = req.body;
      if (!Buffer.isBuffer(buf) || buf.length === 0) {
        res.status(400).json({ error: 'لم يتم استلام بيانات الملف.' });
        return;
      }

      const randomHex = crypto.randomBytes(8).toString('hex');
      const filename = `media_${Date.now()}_${randomHex}.${allowed.ext}`;
      const targetPath = path.join(UPLOAD_DIR, filename);

      await fs.promises.writeFile(targetPath, buf);

      res.json({
        ok: true,
        filename,
        mediaUrl: `/api/media/${filename}`,
        sizeBytes: buf.length,
        mimeType: allowed.mime,
      });
    }
  );

  // Range-enabled Media Streaming Route
  app.get('/api/media/:filename', (req: Request, res: Response) => {
    const filename = String(req.params.filename || '');
    if (!SAFE_MEDIA_FILENAME.test(filename)) {
      res.status(400).json({ error: 'Invalid media identifier.' });
      return;
    }

    const filePath = path.join(UPLOAD_DIR, filename);
    if (!fs.existsSync(filePath)) {
      res.status(404).json({ error: 'Media file not found.' });
      return;
    }

    const ext = filename.split('.').pop() || '';
    const contentType = EXT_TO_MIME[ext] || 'application/octet-stream';
    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;

    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cache-Control', 'public, max-age=604800');

    if (range) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      if (Number.isNaN(start) || start >= fileSize || end >= fileSize || start > end) {
        res.status(416).setHeader('Content-Range', `bytes */${fileSize}`).end();
        return;
      }
      const chunkSize = end - start + 1;
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Content-Length': chunkSize,
        'Content-Type': contentType,
      });
      fs.createReadStream(filePath, { start, end }).pipe(res);
    } else {
      res.writeHead(200, {
        'Content-Length': fileSize,
        'Content-Type': contentType,
      });
      fs.createReadStream(filePath).pipe(res);
    }
  });

  app.delete('/api/media/:filename', rateLimitApi, async (req: Request, res: Response) => {
    const verified = await verifyFirebaseBearer(req.headers.authorization);
    if (!verified) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const filename = String(req.params.filename || '');
    if (!SAFE_MEDIA_FILENAME.test(filename)) {
      res.status(400).json({ error: 'Invalid filename' });
      return;
    }
    const filePath = path.join(UPLOAD_DIR, filename);
    if (fs.existsSync(filePath)) {
      await fs.promises.unlink(filePath);
    }
    res.json({ ok: true });
  });

  app.use(express.json({ limit: '1mb' }));

  app.post('/api/admin/verify-bootstrap', rateLimitApi, (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const body = req.body as { email?: unknown; password?: unknown };
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body?.password === 'string' ? body.password : '';

    if (email !== OWNER_EMAIL || !password) {
      res.status(403).json({ authorized: false });
      return;
    }

    const incomingDigest = crypto.createHash('sha256').update(password).digest();
    const expectedDigest = Buffer.from(OWNER_BOOTSTRAP_DIGEST, 'hex');

    if (
      incomingDigest.length === expectedDigest.length &&
      crypto.timingSafeEqual(incomingDigest, expectedDigest)
    ) {
      res.json({ authorized: true });
      return;
    }

    res.status(403).json({ authorized: false });
  });

  app.get('/api/health', rateLimitApi, (_req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    let mediaCount = 0;
    try {
      mediaCount = fs.readdirSync(UPLOAD_DIR).filter((f) => SAFE_MEDIA_FILENAME.test(f)).length;
    } catch {
      mediaCount = 0;
    }

    res.json({
      status: 'operational',
      service: SITE_ROLE === 'admin' ? 'dark-web-admin' : 'dark-web-portal',
      siteRole: SITE_ROLE,
      nodeVersion: process.version,
      uptimeSeconds: Math.floor(process.uptime()),
      mediaFileCount: mediaCount,
      encryptionStandard: 'AES-256-GCM / PBKDF2-SHA256',
      timestamp: new Date().toISOString(),
    });
  });

  if (!IS_PROD) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(
      express.static(distDir, {
        maxAge: '7d',
        index: false,
      })
    );

    app.get('*', (_req: Request, res: Response) => {
      const indexPath = path.join(distDir, 'index.html');
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(503).send('Build output not found. Run npm run build.');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Dark Web:${SITE_ROLE}] Server listening on 0.0.0.0:${PORT} (${IS_PROD ? 'production' : 'development'})`);
  }).on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`Port ${PORT} is already in use. Retrying or shutting down...`);
      process.exit(1);
    } else {
      throw err;
    }
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
