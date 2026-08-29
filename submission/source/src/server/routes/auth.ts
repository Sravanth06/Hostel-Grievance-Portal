import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';

import {
	createSession,
	destroySession,
	clearSessionCookie,
	requireUser,
	setSessionCookie,
	optionalToken
} from '../auth/session.ts';

import {
	verifyPassword,
	hashPassword,
	needsPasswordUpgrade
} from '../auth/passwords.ts';

import {
	findUserByEmail,
	findUserById
} from '../db/queries.ts';

import { toPublicUser } from '../db/map.ts';
import { HttpError } from '../http/errors.ts';
import { auditLog } from '../db/audit.ts';

export const authRoutes = new Hono<AppEnv>();

/*
 * LOGIN
 *
 * Authentication is performed server-side.
 * The browser never decides whether credentials are valid.
 */
authRoutes.post('/login', async (c) => {
	const db = c.get('db');

	let body: unknown;

	try {
		body = await c.req.json();
	} catch {
		auditLog(
			db,
			c,
			'auth.login.invalid_request'
		);

		throw new HttpError(
			400,
			'bad_request',
			'Request body must be JSON.'
		);
	}

	if (
		!body ||
		typeof body !== 'object'
	) {
		auditLog(
			db,
			c,
			'auth.login.invalid_request'
		);

		throw new HttpError(
			400,
			'bad_request',
			'Request body must be JSON.'
		);
	}

	const email =
		'email' in body &&
		typeof body.email === 'string'
			? body.email
					.trim()
					.toLowerCase()
			: '';

	const password =
		'password' in body &&
		typeof body.password === 'string'
			? body.password
			: '';

	if (!email || !password) {
		auditLog(
			db,
			c,
			'auth.login.missing_credentials'
		);

		throw new HttpError(
			400,
			'bad_request',
			'Email and password are required.'
		);
	}

	const user =
		findUserByEmail(
			db,
			email
		);

	/*
	 * Do not reveal whether the email exists.
	 */
	if (
		!user ||
		!(
			await verifyPassword(
				password,
				user.password_hash
			)
		)
	) {
		auditLog(
			db,
			c,
			'auth.login.failed',
			{
				details: {
					email
				}
			}
		);

		throw new HttpError(
			401,
			'unauthenticated',
			'Invalid email or password.'
		);
	}

	/*
	 * Upgrade legacy SHA-256 hashes to Argon2id
	 * after successful authentication.
	 */
	if (
		needsPasswordUpgrade(
			user.password_hash
		)
	) {
		const upgradedHash =
			await hashPassword(
				password
			);

		db.prepare(
			`
			UPDATE users
			SET password_hash = ?
			WHERE id = ?
			`
		).run(
			upgradedHash,
			user.id
		);
	}

	/*
	 * Create a fresh server-side session.
	 */
	const token =
		createSession(
			db,
			user.id
		);

	setSessionCookie(
		c,
		token
	);

	auditLog(
		db,
		c,
		'auth.login.success',
		{
			userId: user.id,
			details: {
				role: user.role
			}
		}
	);

	/*
	 * Only public user information is returned.
	 * password_hash is never exposed.
	 */
	return c.json({
		user:
			toPublicUser(user)
	});
});

/*
 * LOGOUT
 *
 * Destroys the server-side session
 * and clears the browser cookie.
 */
authRoutes.post('/logout', (c) => {
	const db = c.get('db');

	const token =
		optionalToken(c);

	let userId:
		| string
		| null = null;

	if (token) {
		/*
		 * Identify the current user before
		 * destroying the session.
		 */
		const sessionUser =
			(() => {
				try {
					return requireUser(
						c,
						db
					);
				} catch {
					return undefined;
				}
			})();

		userId =
			sessionUser?.id ??
			null;

		destroySession(
			db,
			token
		);
	}

	clearSessionCookie(c);

	auditLog(
		db,
		c,
		'auth.logout',
		{
			userId
		}
	);

	return c.json({
		ok: true
	});
});

/*
 * CURRENT USER
 *
 * The authenticated user is determined from
 * the server-side session.
 */
authRoutes.get('/me', (c) => {
	const db = c.get('db');

	const user =
		requireUser(
			c,
			db
		);

	/*
	 * Confirm that the user still exists.
	 */
	const currentUser =
		findUserById(
			db,
			user.id
		);

	if (!currentUser) {
		const token =
			optionalToken(c);

		if (token) {
			destroySession(
				db,
				token
			);
		}

		clearSessionCookie(c);

		auditLog(
			db,
			c,
			'auth.session.invalid_user',
			{
				userId: user.id
			}
		);

		throw new HttpError(
			401,
			'unauthenticated',
			'Authentication required.'
		);
	}

	return c.json({
		user:
			toPublicUser(
				currentUser
			)
	});
});