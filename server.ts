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

const rateBuckets = new Map<string, { count: number; resetAt: number }>();

function rateLimitApi(req: Request, res: Response, next: NextFunction): void {
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60_000;
  const maxRequests = 120;

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

async function startServer(): Promise<void> {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(securityHeaders);
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
    res.json({
      status: 'operational',
      service: SITE_ROLE === 'admin' ? 'dark-web-admin' : 'dark-web-portal',
      siteRole: SITE_ROLE,
      nodeVersion: process.version,
      uptimeSeconds: Math.floor(process.uptime()),
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
