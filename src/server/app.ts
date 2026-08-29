import { Hono } from 'hono';
import type { Database } from 'better-sqlite3';
import type { AppEnv } from './env.ts';
import { handleError, HttpError } from './http/errors.ts';
import { authRoutes } from './routes/auth.ts';
import { grievanceRoutes } from './routes/grievances.ts';
import { attachmentRoutes } from './routes/attachments.ts';
import { cors } from 'hono/cors';

export type CreateAppOptions = {
	db: Database;
	uploadsDir: string;
};

/*
 * Only allow explicitly trusted browser origins.
 *
 * Authentication uses cookies, so arbitrary origins must
 * never receive credentialed CORS responses.
 */
function allowedOrigin(
	origin: string | undefined
): string | undefined {
	const configuredOrigins = (
		process.env.HOSTEL_ALLOWED_ORIGINS ??
		'http://localhost:5173,http://127.0.0.1:5173'
	)
		.split(',')
		.map((value) => value.trim())
		.filter(Boolean);

	if (!origin) {
		return undefined;
	}

	return configuredOrigins.includes(origin)
		? origin
		: undefined;
}

/*
 * Apply browser-facing security headers.
 *
 * These controls are defense-in-depth.
 * Authentication and authorization are still enforced
 * server-side by the individual routes.
 */
function applySecurityHeaders(c: any): void {
	/*
	 * Prevent MIME sniffing.
	 */
	c.header(
		'X-Content-Type-Options',
		'nosniff'
	);

	/*
	 * Prevent the application from being embedded
	 * in another website.
	 */
	c.header(
		'X-Frame-Options',
		'DENY'
	);

	/*
	 * Limit referrer information sent to other origins.
	 */
	c.header(
		'Referrer-Policy',
		'strict-origin-when-cross-origin'
	);

	/*
	 * Disable browser capabilities that the application
	 * does not require.
	 */
	c.header(
		'Permissions-Policy',
		'camera=(), microphone=(), geolocation=(), payment=()'
	);

	/*
	 * Do not allow authenticated API responses to be cached
	 * by browsers or shared proxies.
	 */
	if (c.req.path.startsWith('/api/')) {
		c.header(
			'Cache-Control',
			'no-store'
		);
	}
}

export function createApp(
	options: CreateAppOptions
) {
	const app = new Hono<AppEnv>();

	/*
	 * Apply security headers to every response.
	 */
	app.use('*', async (c, next) => {
		applySecurityHeaders(c);
		await next();
	});

	/*
	 * Attach trusted server-side resources to the request
	 * context.
	 */
	app.use('*', async (c, next) => {
		c.set('db', options.db);
		c.set(
			'uploadsDir',
			options.uploadsDir
		);

		await next();
	});

	/*
	 * Credentialed CORS with an explicit origin allowlist.
	 */
	app.use(
		'/api/*',
		cors({
			origin: (origin) =>
				allowedOrigin(origin),
			credentials: true
		})
	);

	/*
	 * Centralized error handling.
	 */
	app.onError((err, c) =>
		handleError(err, c)
	);

	app.notFound((c) =>
		c.json(
			{
				error: 'Not found.',
				code: 'not_found'
			},
			404
		)
	);

	/*
	 * Health endpoint.
	 */
	app.get(
		'/api/health',
		(c) => c.json({ ok: true })
	);

	/*
	 * Authentication routes.
	 */
	app.route(
		'/api',
		authRoutes
	);

	/*
	 * Grievance routes.
	 */
	app.route(
		'/api/grievances',
		grievanceRoutes
	);

	/*
	 * Attachment routes.
	 */
	app.route(
		'/api/attachments',
		attachmentRoutes
	);

	/*
	 * API fallback.
	 */
	app.all('/api/*', () => {
		throw new HttpError(
			404,
			'not_found',
			'Not found.'
		);
	});

	return app;
}