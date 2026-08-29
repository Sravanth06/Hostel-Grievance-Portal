import { randomBytes } from 'node:crypto';
import type { Database } from 'better-sqlite3';
import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { SESSION_COOKIE, SESSION_TTL_SECONDS } from '../config.ts';
import { HttpError } from '../http/errors.ts';
import type { SessionUser } from '../types/index.ts';

function nowIso(): string {
	return new Date().toISOString();
}

function expiryIso(): string {
	return new Date(
		Date.now() + SESSION_TTL_SECONDS * 1000
	).toISOString();
}

/**
 * Creates a cryptographically random server-side session.
 *
 * The browser receives only the opaque session token.
 * All authorization decisions remain server-side.
 */
export function createSession(
	db: Database,
	userId: string
): string {
	const token = randomBytes(32).toString('base64url');

	db.prepare(
		`
		INSERT INTO sessions
			(token, user_id, created_at, expires_at)
		VALUES
			(?, ?, ?, ?)
		`
	).run(
		token,
		userId,
		nowIso(),
		expiryIso()
	);

	return token;
}

/**
 * Destroys a server-side session.
 */
export function destroySession(
	db: Database,
	token: string
): void {
	db.prepare(
		'DELETE FROM sessions WHERE token = ?'
	).run(token);
}

/**
 * Reads the authenticated user from a session token.
 *
 * Expired sessions are rejected and removed.
 */
export function readSessionUser(
	db: Database,
	token: string
): SessionUser | undefined {
	const row = db
		.prepare(
			`
			SELECT
				u.id,
				u.name,
				u.email,
				u.role,
				u.room,
				u.created_at,
				s.expires_at
			FROM sessions s
			JOIN users u
				ON u.id = s.user_id
			WHERE s.token = ?
			`
		)
		.get(token) as
		| (SessionUser & { expires_at: string })
		| undefined;

	if (!row) {
		return undefined;
	}

	/*
	 * Security boundary:
	 * An expired token must never remain usable.
	 */
	if (
		!row.expires_at ||
		Date.parse(row.expires_at) <= Date.now()
	) {
		db.prepare(
			'DELETE FROM sessions WHERE token = ?'
		).run(token);

		return undefined;
	}

	return {
		id: row.id,
		name: row.name,
		email: row.email,
		role: row.role,
		room: row.room,
		created_at: row.created_at
	};
}

/**
 * Sets the authentication cookie.
 *
 * httpOnly:
 *   Prevents frontend JavaScript from reading the session token.
 *
 * sameSite=Lax:
 *   Reduces cross-site request abuse while preserving normal
 *   application navigation.
 *
 * secure:
 *   Required when deployed over HTTPS.
 *   Disabled for local HTTP development.
 */
export function setSessionCookie(
	c: Context,
	token: string
): void {
	const isProduction =
		process.env.NODE_ENV === 'production';

	setCookie(
		c,
		SESSION_COOKIE,
		token,
		{
			path: '/',
			maxAge: SESSION_TTL_SECONDS,
			httpOnly: true,
			sameSite: 'Lax',
			secure: isProduction
		}
	);
}

/**
 * Removes the authentication cookie.
 */
export function clearSessionCookie(
	c: Context
): void {
	deleteCookie(
		c,
		SESSION_COOKIE,
		{
			path: '/',
			httpOnly: true,
			sameSite: 'Lax',
			secure:
				process.env.NODE_ENV === 'production'
		}
	);
}

/**
 * Requires a valid authenticated session.
 */
export function requireUser(
	c: Context,
	db: Database
): SessionUser {
	const token = getCookie(
		c,
		SESSION_COOKIE
	);

	if (!token) {
		throw new HttpError(
			401,
			'unauthenticated',
			'Authentication required.'
		);
	}

	const user = readSessionUser(
		db,
		token
	);

	if (!user) {
		throw new HttpError(
			401,
			'unauthenticated',
			'Authentication required.'
		);
	}

	return user;
}

/**
 * Returns the raw session token when present.
 *
 * This is used only for server-side session management.
 * Never expose this value to the client or audit logs.
 */
export function optionalToken(
	c: Context
): string | undefined {
	return getCookie(
		c,
		SESSION_COOKIE
	);
}