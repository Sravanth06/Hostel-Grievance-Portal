import type { Context } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { ErrorCode } from '../types/index.ts';

export class HttpError extends Error {
	readonly status: ContentfulStatusCode;
	readonly code: ErrorCode;

	constructor(
		status: ContentfulStatusCode,
		code: ErrorCode,
		message: string
	) {
		super(message);
		this.name = 'HttpError';
		this.status = status;
		this.code = code;
	}
}

export function jsonError(
	c: Context,
	status: ContentfulStatusCode,
	code: ErrorCode,
	error: string
) {
	return c.json({ error, code }, status);
}

/**
 * Central error handler.
 *
 * Expected application errors are returned to the client.
 * Unexpected errors are logged server-side but their internal
 * details are NEVER exposed to the client.
 */
export function handleError(err: unknown, c: Context) {
	if (err instanceof HttpError) {
		return jsonError(
			c,
			err.status,
			err.code,
			err.message
		);
	}

	// Security boundary:
	// Never send database paths, SQL errors, stack traces,
	// filesystem paths, or runtime internals to the client.
	console.error('[SECURITY] Unexpected application error', {
		method: c.req.method,
		path: c.req.path,
		timestamp: new Date().toISOString(),
		error:
			err instanceof Error
				? {
						name: err.name,
						message: err.message,
						stack: err.stack
					}
				: String(err)
	});

	return jsonError(
		c,
		500,
		'internal',
		'Internal server error.'
	);
}