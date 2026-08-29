import {
	mkdirSync,
	writeFileSync,
	readFileSync,
	existsSync,
	rmSync,
	readdirSync
} from 'node:fs';

import { join, resolve, sep } from 'node:path';
import { randomBytes } from 'node:crypto';

import {
	ALLOWED_ATTACHMENT_TYPES,
	MAX_ATTACHMENT_BYTES
} from '../config.ts';

import { HttpError } from '../http/errors.ts';

const MIME_EXTENSION: Record<string, string> = {
	'image/jpeg': '.jpg',
	'image/png': '.png',
	'image/gif': '.gif',
	'image/webp': '.webp'
};

/**
 * Validate the actual file contents.
 *
 * The browser supplied MIME type is untrusted, so we also
 * inspect the file signature (magic bytes).
 */
function hasValidSignature(
	mime: string,
	bytes: Buffer
): boolean {
	switch (mime) {
		case 'image/png':
			return (
				bytes.length >= 8 &&
				bytes.subarray(0, 8).equals(
					Buffer.from([
						0x89,
						0x50,
						0x4e,
						0x47,
						0x0d,
						0x0a,
						0x1a,
						0x0a
					])
				)
			);

		case 'image/jpeg':
			return (
				bytes.length >= 3 &&
				bytes[0] === 0xff &&
				bytes[1] === 0xd8 &&
				bytes[2] === 0xff
			);

		case 'image/gif':
			return (
				bytes.length >= 6 &&
				(
					bytes.subarray(0, 6).toString('ascii') ===
						'GIF87a' ||
					bytes.subarray(0, 6).toString('ascii') ===
						'GIF89a'
				)
			);

		case 'image/webp':
			return (
				bytes.length >= 12 &&
				bytes.subarray(0, 4).toString('ascii') ===
					'RIFF' &&
				bytes.subarray(8, 12).toString('ascii') ===
					'WEBP'
			);

		default:
			return false;
	}
}

export function ensureUploadsDir(
	dir: string
): void {
	mkdirSync(
		dir,
		{ recursive: true }
	);
}

export function resetUploadsDir(
	dir: string
): void {
	if (existsSync(dir)) {
		rmSync(
			dir,
			{
				recursive: true,
				force: true
			}
		);
	}

	mkdirSync(
		dir,
		{ recursive: true }
	);
}

export function originalBasename(
	filename: string
): string {
	const base =
		filename
			.replace(/\\/g, '/')
			.split('/')
			.pop() ?? 'upload';

	const cleaned =
		base
			.replace(/[\0\r\n]/g, '')
			.trim();

	return cleaned.length > 0
		? cleaned.slice(0, 255)
		: 'upload';
}

export function extensionForMime(
	mime: string
): string {
	return MIME_EXTENSION[mime] ?? '.bin';
}

/**
 * Generate a random server-side filename.
 *
 * The original filename is never used as the
 * physical filesystem filename.
 */
export function newStoredName(
	mime: string
): string {
	return (
		randomBytes(16).toString('hex') +
		extensionForMime(mime)
	);
}

/**
 * Validate both declared metadata and actual file contents.
 */
export function assertPermittedAttachment(
	mime: string,
	size: number,
	bytes?: Buffer
): void {
	if (
		!ALLOWED_ATTACHMENT_TYPES.has(mime)
	) {
		throw new HttpError(
			400,
			'bad_request',
			'Attachments must be JPEG, PNG, GIF, or WebP images.'
		);
	}

	if (size <= 0) {
		throw new HttpError(
			400,
			'bad_request',
			'Attachment file is empty.'
		);
	}

	if (
		size > MAX_ATTACHMENT_BYTES
	) {
		throw new HttpError(
			400,
			'bad_request',
			'Attachment must be 2 MB or smaller.'
		);
	}

	/*
	 * Security boundary:
	 * Never rely only on File.type because it is
	 * controlled by the uploading client.
	 */
	if (
		bytes &&
		!hasValidSignature(
			mime,
			bytes
		)
	) {
		throw new HttpError(
			400,
			'bad_request',
			'Attachment contents do not match the declared image type.'
		);
	}
}

export async function bufferFromUpload(
	file: File
): Promise<Buffer> {
	const bytes =
		Buffer.from(
			await file.arrayBuffer()
		);

	assertPermittedAttachment(
		file.type,
		bytes.byteLength,
		bytes
	);

	return bytes;
}

/**
 * Store only server-generated filenames.
 */
export function writeStoredFile(
	uploadsDir: string,
	storedName: string,
	bytes: Buffer
): void {
	ensureUploadsDir(
		uploadsDir
	);

	/*
	 * Defense-in-depth:
	 * Reject unexpected path components even though
	 * callers normally provide generated filenames.
	 */
	if (
		storedName.includes('/') ||
		storedName.includes('\\') ||
		storedName.includes('..')
	) {
		throw new HttpError(
			400,
			'bad_request',
			'Invalid stored filename.'
		);
	}

	writeFileSync(
		join(
			uploadsDir,
			storedName
		),
		bytes,
		{
			flag: 'wx'
		}
	);
}

export function readStoredFile(
	uploadsDir: string,
	storedName: string
): Buffer {
	/*
	 * Defense against path traversal.
	 */
	if (
		storedName.includes('/') ||
		storedName.includes('\\') ||
		storedName.includes('..')
	) {
		throw new HttpError(
			404,
			'not_found',
			'Attachment file was not found.'
		);
	}

	const root =
		resolve(uploadsDir);

	const full =
		resolve(
			join(
				uploadsDir,
				storedName
			)
		);

	/*
	 * Defense-in-depth path boundary check.
	 */
	if (
		full !== root &&
		!full.startsWith(
			root + sep
		)
	) {
		throw new HttpError(
			404,
			'not_found',
			'Attachment file was not found.'
		);
	}

	if (!existsSync(full)) {
		throw new HttpError(
			404,
			'not_found',
			'Attachment file was not found.'
		);
	}

	return readFileSync(full);
}

export function listStoredNames(
	uploadsDir: string
): string[] {
	if (!existsSync(uploadsDir)) {
		return [];
	}

	return readdirSync(
		uploadsDir
	).filter(
		(name) =>
			name !== '.gitkeep'
	);
}