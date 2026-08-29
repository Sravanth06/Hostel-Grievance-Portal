import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import { requireUser } from '../auth/session.ts';
import { findAttachmentRow, requireGrievance } from '../db/queries.ts';
import { readStoredFile } from '../storage/attachments.ts';
import { HttpError } from '../http/errors.ts';

export const attachmentRoutes = new Hono<AppEnv>();

attachmentRoutes.get('/:id', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);

	const attachmentId = c.req.param('id');

	const row = findAttachmentRow(db, attachmentId);

	if (!row) {
		throw new HttpError(
			404,
			'not_found',
			'Attachment was not found.'
		);
	}

	/*
	 * Find the grievance that owns this attachment.
	 */
	const grievance = requireGrievance(
		db,
		row.grievance_id
	);

	/*
	 * Object-level authorization:
	 *
	 * Wardens can access attachments for any grievance.
	 * Students can access attachments only when the
	 * grievance belongs to them.
	 */
	if (
		user.role === 'student' &&
		grievance.student_id !== user.id
	) {
		throw new HttpError(
			403,
			'unauthorized',
			'You are not authorized to access this attachment.'
		);
	}

	const bytes = readStoredFile(
		c.get('uploadsDir'),
		row.stored_filename
	);

	c.header(
		'Content-Type',
		row.mime_type
	);

	c.header(
		'Content-Length',
		String(bytes.length)
	);

	c.header(
		'Content-Disposition',
		`inline; filename="${row.original_filename.replaceAll('"', '')}"`
	);

	return c.body(
		new Uint8Array(bytes)
	);
});