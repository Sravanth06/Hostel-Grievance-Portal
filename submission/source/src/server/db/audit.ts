import type { Database } from 'better-sqlite3';
import type { Context } from 'hono';
import { randomUUID } from 'node:crypto';

function nowIso(): string {
	return new Date().toISOString();
}

/**
 * Records security-relevant activity.
 *
 * IMPORTANT:
 * - Never store passwords.
 * - Never store session tokens.
 * - Never store uploaded file contents.
 * - Keep details limited to information useful for investigation.
 */
export function auditLog(
	db: Database,
	c: Context,
	event: string,
	options: {
		userId?: string | null;
		details?: Record<string, unknown>;
	} = {}
): void {
	try {
		const details = options.details
			? JSON.stringify(options.details)
			: null;

		db.prepare(
			`
			INSERT INTO audit_logs
				(id, event, user_id, ip_address, method, path, details, created_at)
			VALUES
				(@id, @event, @user_id, @ip_address, @method, @path, @details, @created_at)
			`
		).run({
			id: randomUUID(),
			event,
			user_id: options.userId ?? null,
			ip_address: getClientIp(c),
			method: c.req.method,
			path: c.req.path,
			details,
			created_at: nowIso()
		});
	} catch (error) {
		/*
		 * Audit logging must never break the main application.
		 * If logging fails, record the failure server-side.
		 */
		console.error('[SECURITY] Failed to write audit log', {
			event,
			method: c.req.method,
			path: c.req.path,
			error:
				error instanceof Error
					? error.message
					: String(error)
		});
	}
}

/**
 * Extract the client IP when the deployment provides it.
 *
 * The value is used for investigation only.
 * It is never trusted for authorization.
 */
function getClientIp(c: Context): string | null {
	const forwardedFor =
		c.req.header('x-forwarded-for');

	if (forwardedFor) {
		return (
			forwardedFor
				.split(',')[0]
				?.trim() || null
		);
	}

	return (
		c.req.header('x-real-ip') ??
		null
	);
}