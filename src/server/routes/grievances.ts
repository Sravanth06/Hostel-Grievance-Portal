import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';

import { requireUser } from '../auth/session.ts';

import {
	assembleGrievance,
	findUserById,
	listAllGrievanceRows,
	listCommentRows,
	listGrievanceRowsForStudent,
	nextAttachmentId,
	nextCommentId,
	nextGrievanceId,
	requireGrievance,
	touchGrievance
} from '../db/queries.ts';

import type {
	CommentRow,
	AttachmentRow,
	GrievanceStatusDb
} from '../types/index.ts';

import {
	toPublicAttachment,
	toPublicComment,
	toPublicUser
} from '../db/map.ts';

import { HttpError } from '../http/errors.ts';
import { parseCategory, statusToDb } from '../http/status.ts';

import {
	bufferFromUpload,
	newStoredName,
	originalBasename,
	writeStoredFile
} from '../storage/attachments.ts';

function nowIso(): string {
	return new Date().toISOString();
}

function readString(
	value: unknown
): string | undefined {
	return typeof value === 'string'
		? value
		: undefined;
}

/*
 * Input limits.
 *
 * These limits protect the API/database from unnecessarily
 * large user-controlled text while preserving normal usage.
 */
const MAX_TITLE_LENGTH = 200;
const MAX_DESCRIPTION_LENGTH = 5000;
const MAX_COMMENT_LENGTH = 2000;

export const grievanceRoutes =
	new Hono<AppEnv>();

/*
 * GET ALL GRIEVANCES
 *
 * Warden:
 *   Can see all grievances.
 *
 * Student:
 *   Can see only their own grievances.
 */
grievanceRoutes.get('/', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);

	const rows =
		user.role === 'warden'
			? listAllGrievanceRows(db)
			: listGrievanceRowsForStudent(
					db,
					user.id
				);

	return c.json({
		data: rows.map((row) =>
			assembleGrievance(db, row)
		)
	});
});

/*
 * CREATE GRIEVANCE
 *
 * Only students can create grievances.
 */
grievanceRoutes.post(
	'/',
	async (c) => {
		const db = c.get('db');
		const uploadsDir =
			c.get('uploadsDir');

		const user =
			requireUser(c, db);

		if (
			user.role !== 'student'
		) {
			throw new HttpError(
				403,
				'unauthorized',
				'Only students can file grievances.'
			);
		}

		const contentType =
			c.req.header(
				'content-type'
			) ?? '';

		let title = '';
		let category = '';
		let description = '';
		let upload:
			| File
			| undefined;

		/*
		 * Support both JSON and multipart/form-data.
		 */
		if (
			contentType.includes(
				'multipart/form-data'
			)
		) {
			const body =
				await c.req.parseBody();

			title =
				readString(
					body.title
				) ?? '';

			category =
				readString(
					body.category
				) ?? '';

			description =
				readString(
					body.description
				) ?? '';

			if (
				body.file instanceof File
			) {
				upload = body.file;
			} else if (
				body.attachment instanceof File
			) {
				upload =
					body.attachment;
			}
		} else {
			let json: unknown;

			try {
				json =
					await c.req.json();
			} catch {
				throw new HttpError(
					400,
					'bad_request',
					'Request body must be JSON or multipart form data.'
				);
			}

			if (
				!json ||
				typeof json !== 'object'
			) {
				throw new HttpError(
					400,
					'bad_request',
					'Request body must be JSON or multipart form data.'
				);
			}

			title =
				readString(
					'title' in json
						? json.title
						: undefined
				) ?? '';

			category =
				readString(
					'category' in json
						? json.category
						: undefined
				) ?? '';

			description =
				readString(
					'description' in json
						? json.description
						: undefined
				) ?? '';
		}

		title = title.trim();
		description =
			description.trim();

		/*
		 * Validate title length.
		 */
		if (
			title.length < 5 ||
			title.length >
				MAX_TITLE_LENGTH
		) {
			throw new HttpError(
				400,
				'bad_request',
				'Title must be between 5 and 200 characters.'
			);
		}

		/*
		 * Validate description length.
		 */
		if (
			description.length < 20 ||
			description.length >
				MAX_DESCRIPTION_LENGTH
		) {
			throw new HttpError(
				400,
				'bad_request',
				'Description must be between 20 and 5000 characters.'
			);
		}

		/*
		 * Category is validated against an explicit
		 * server-side allowlist.
		 */
		const parsedCategory =
			parseCategory(category);

		const id =
			nextGrievanceId(db);

		const ts =
			nowIso();

		db.prepare(
			`
			INSERT INTO grievances
				(id, student_id, title, category,
				 description, status, created_at, updated_at)
			VALUES
				(?, ?, ?, ?, ?, 'open', ?, ?)
			`
		).run(
			id,
			user.id,
			title,
			parsedCategory,
			description,
			ts,
			ts
		);

		/*
		 * Optional attachment during grievance creation.
		 */
		if (upload) {
			const bytes =
				await bufferFromUpload(
					upload
				);

			/*
			 * Never use the user-supplied filename
			 * as the physical filesystem filename.
			 */
			const stored =
				newStoredName(
					upload.type
				);

			writeStoredFile(
				uploadsDir,
				stored,
				bytes
			);

			db.prepare(
				`
				INSERT INTO attachments
					(id, grievance_id,
					 original_filename,
					 stored_filename,
					 mime_type,
					 size_bytes,
					 created_at)
				VALUES
					(?, ?, ?, ?, ?, ?, ?)
				`
			).run(
				nextAttachmentId(db),
				id,
				originalBasename(
					upload.name
				),
				stored,
				upload.type,
				bytes.byteLength,
				ts
			);
		}

		return c.json(
			{
				data:
					assembleGrievance(
						db,
						requireGrievance(
							db,
							id
						)
					)
			},
			201
		);
	}
);

/*
 * GET COMMENTS
 *
 * Warden:
 *   Can view comments on any grievance.
 *
 * Student:
 *   Can view comments only on their own grievance.
 */
grievanceRoutes.get(
	'/:id/comments',
	(c) => {
		const db =
			c.get('db');

		const user =
			requireUser(
				c,
				db
			);

		const row =
			requireGrievance(
				db,
				c.req.param('id')
			);

		if (
			user.role === 'student' &&
			row.student_id !== user.id
		) {
			throw new HttpError(
				403,
				'unauthorized',
				'You are not authorized to view these comments.'
			);
		}

		const comments =
			listCommentRows(
				db,
				row.id
			).map(
				(comment) => {
					const authorRow =
						findUserById(
							db,
							comment.author_id
						);

					if (!authorRow) {
						throw new HttpError(
							500,
							'internal',
							'Internal server error.'
						);
					}

					return toPublicComment(
						comment,
						toPublicUser(
							authorRow
						)
					);
				}
			);

		return c.json({
			data: comments
		});
	}
);

/*
 * ADD COMMENT
 *
 * Warden:
 *   Can comment on any grievance.
 *
 * Student:
 *   Can comment only on their own grievance.
 */
grievanceRoutes.post(
	'/:id/comments',
	async (c) => {
		const db =
			c.get('db');

		const user =
			requireUser(
				c,
				db
			);

		const row =
			requireGrievance(
				db,
				c.req.param('id')
			);

		if (
			user.role === 'student' &&
			row.student_id !== user.id
		) {
			throw new HttpError(
				403,
				'unauthorized',
				'You are not authorized to comment on this grievance.'
			);
		}

		let body: unknown;

		try {
			body =
				await c.req.json();
		} catch {
			throw new HttpError(
				400,
				'bad_request',
				'JSON body is required.'
			);
		}

		const text =
			body &&
			typeof body === 'object' &&
			'body' in body &&
			typeof body.body ===
				'string'
				? body.body.trim()
				: '';

		/*
		 * Prevent empty or excessively large comments.
		 */
		if (
			!text ||
			text.length >
				MAX_COMMENT_LENGTH
		) {
			throw new HttpError(
				400,
				'bad_request',
				'Comment must be between 1 and 2000 characters.'
			);
		}

		const id =
			nextCommentId(db);

		const ts =
			nowIso();

		db.prepare(
			`
			INSERT INTO comments
				(id, grievance_id, author_id,
				 body, created_at)
			VALUES
				(?, ?, ?, ?, ?)
			`
		).run(
			id,
			row.id,
			user.id,
			text,
			ts
		);

		touchGrievance(
			db,
			row.id,
			ts
		);

		const author =
			findUserById(
				db,
				user.id
			);

		if (!author) {
			throw new HttpError(
				500,
				'internal',
				'Internal server error.'
			);
		}

		const commentRow =
			db
				.prepare(
					'SELECT * FROM comments WHERE id = ?'
				)
				.get(
					id
				) as CommentRow;

		return c.json(
			{
				data:
					toPublicComment(
						commentRow,
						toPublicUser(
							author
						)
					)
			},
			201
		);
	}
);

/*
 * ADD ATTACHMENT
 *
 * Only the student who owns the grievance
 * can add an attachment.
 */
grievanceRoutes.post(
	'/:id/attachments',
	async (c) => {
		const db =
			c.get('db');

		const user =
			requireUser(
				c,
				db
			);

		const row =
			requireGrievance(
				db,
				c.req.param('id')
			);

		if (
			user.role !== 'student' ||
			row.student_id !== user.id
		) {
			throw new HttpError(
				403,
				'unauthorized',
				'Only the student owner can add attachments.'
			);
		}

		if (
			row.status ===
			'resolved'
		) {
			throw new HttpError(
				409,
				'conflict',
				'Resolved grievances cannot be edited.'
			);
		}

		const body =
			await c.req.parseBody();

		const upload =
			body.file instanceof File
				? body.file
				: body.attachment instanceof File
					? body.attachment
					: undefined;

		if (!upload) {
			throw new HttpError(
				400,
				'bad_request',
				'A file field named file is required.'
			);
		}

		/*
		 * Validates declared MIME type,
		 * size and actual file signature.
		 */
		const bytes =
			await bufferFromUpload(
				upload
			);

		/*
		 * Generate random server-side filename.
		 */
		const stored =
			newStoredName(
				upload.type
			);

		const ts =
			nowIso();

		writeStoredFile(
			c.get('uploadsDir'),
			stored,
			bytes
		);

		const id =
			nextAttachmentId(
				db
			);

		db.prepare(
			`
			INSERT INTO attachments
				(id, grievance_id,
				 original_filename,
				 stored_filename,
				 mime_type,
				 size_bytes,
				 created_at)
			VALUES
				(?, ?, ?, ?, ?, ?, ?)
			`
		).run(
			id,
			row.id,
			originalBasename(
				upload.name
			),
			stored,
			upload.type,
			bytes.byteLength,
			ts
		);

		touchGrievance(
			db,
			row.id,
			ts
		);

		const saved =
			db
				.prepare(
					'SELECT * FROM attachments WHERE id = ?'
				)
				.get(
					id
				) as AttachmentRow;

		return c.json(
			{
				data:
					toPublicAttachment(
						saved
					)
			},
			201
		);
	}
);

/*
 * GET SINGLE GRIEVANCE
 *
 * Warden:
 *   Can access any grievance.
 *
 * Student:
 *   Can access only their own grievance.
 */
grievanceRoutes.get(
	'/:id',
	(c) => {
		const db =
			c.get('db');

		const user =
			requireUser(
				c,
				db
			);

		const row =
			requireGrievance(
				db,
				c.req.param('id')
			);

		if (
			user.role === 'student' &&
			row.student_id !== user.id
		) {
			throw new HttpError(
				403,
				'unauthorized',
				'You are not authorized to access this grievance.'
			);
		}

		return c.json({
			data:
				assembleGrievance(
					db,
					row
				)
		});
	}
);

/*
 * UPDATE GRIEVANCE
 *
 * Student:
 *   - Can edit own grievance content.
 *   - Cannot edit another student's grievance.
 *   - Cannot edit resolved grievance.
 *   - Cannot change status.
 *
 * Warden:
 *   - Can change status.
 *   - Cannot modify student-authored content.
 */
grievanceRoutes.patch(
	'/:id',
	async (c) => {
		const db =
			c.get('db');

		const user =
			requireUser(
				c,
				db
			);

		const row =
			requireGrievance(
				db,
				c.req.param('id')
			);

		let body: unknown;

		try {
			body =
				await c.req.json();
		} catch {
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
			throw new HttpError(
				400,
				'bad_request',
				'Request body must be JSON.'
			);
		}

		const title =
			'title' in body
				? body.title
				: undefined;

		const description =
			'description' in body
				? body.description
				: undefined;

		const category =
			'category' in body
				? body.category
				: undefined;

		const status =
			'status' in body
				? body.status
				: undefined;

		const wantsContent =
			title !== undefined ||
			description !== undefined ||
			category !== undefined;

		const wantsStatus =
			status !== undefined;

		if (
			!wantsContent &&
			!wantsStatus
		) {
			throw new HttpError(
				400,
				'bad_request',
				'No updatable fields were provided.'
			);
		}

		switch (user.role) {
			case 'student': {
				/*
				 * Object-level authorization.
				 */
				if (
					row.student_id !==
					user.id
				) {
					throw new HttpError(
						403,
						'unauthorized',
						'You are not authorized to modify this grievance.'
					);
				}

				if (
					row.status ===
					'resolved'
				) {
					throw new HttpError(
						409,
						'conflict',
						'Resolved grievances cannot be edited.'
					);
				}

				/*
				 * Students cannot control workflow status.
				 */
				if (
					status !== undefined
				) {
					throw new HttpError(
						403,
						'unauthorized',
						'Students cannot change grievance status.'
					);
				}

				let nextTitle =
					row.title;

				let nextDescription =
					row.description;

				let nextCategory =
					row.category;

				const nextStatus:
					GrievanceStatusDb =
						row.status;

				if (
					title !== undefined
				) {
					if (
						typeof title !==
							'string' ||
						title.trim()
							.length < 5 ||
						title.trim()
							.length >
							MAX_TITLE_LENGTH
					) {
						throw new HttpError(
							400,
							'bad_request',
							'Title must be between 5 and 200 characters.'
						);
					}

					nextTitle =
						title.trim();
				}

				if (
					description !==
					undefined
				) {
					if (
						typeof description !==
							'string' ||
						description.trim()
							.length < 20 ||
						description.trim()
							.length >
							MAX_DESCRIPTION_LENGTH
					) {
						throw new HttpError(
							400,
							'bad_request',
							'Description must be between 20 and 5000 characters.'
						);
					}

					nextDescription =
						description.trim();
				}

				if (
					category !==
					undefined
				) {
					if (
						typeof category !==
						'string'
					) {
						throw new HttpError(
							400,
							'bad_request',
							'Invalid grievance category.'
						);
					}

					nextCategory =
						parseCategory(
							category
						);
				}

				const ts =
					nowIso();

				db.prepare(
					`
					UPDATE grievances
					SET
						title = ?,
						description = ?,
						category = ?,
						status = ?,
						updated_at = ?
					WHERE id = ?
					`
				).run(
					nextTitle,
					nextDescription,
					nextCategory,
					nextStatus,
					ts,
					row.id
				);

				break;
			}

			case 'warden': {
				/*
				 * Wardens manage workflow status.
				 * They cannot alter student content.
				 */
				if (
					wantsContent
				) {
					throw new HttpError(
						403,
						'unauthorized',
						'Wardens cannot edit grievance content.'
					);
				}

				if (
					typeof status !==
					'string'
				) {
					throw new HttpError(
						400,
						'bad_request',
						'Invalid grievance status.'
					);
				}

				const nextStatus =
					statusToDb(
						status
					);

				const ts =
					nowIso();

				db.prepare(
					`
					UPDATE grievances
					SET status = ?, updated_at = ?
					WHERE id = ?
					`
				).run(
					nextStatus,
					ts,
					row.id
				);

				break;
			}

			default: {
				const _exhaustive:
					never =
					user.role;

				throw new HttpError(
					500,
					'internal',
					'Internal server error.'
				);

				void _exhaustive;
			}
		}

		return c.json({
			data:
				assembleGrievance(
					db,
					requireGrievance(
						db,
						row.id
					)
				)
		});
	}
);