import argon2 from 'argon2';
import { createHash, timingSafeEqual } from 'node:crypto';

/*
 * Password hashing
 *
 * Argon2id is designed specifically for password storage.
 * It is intentionally expensive to make offline password
 * guessing substantially harder.
 */
export async function hashPassword(password: string): Promise<string> {
	return argon2.hash(password, {
		type: argon2.argon2id
	});
}

/*
 * Verify passwords stored using either:
 *
 * 1. Argon2id - hardened password storage.
 * 2. Legacy SHA-256 - supported temporarily for migration
 *    of the existing challenge database.
 */
export async function verifyPassword(
	password: string,
	stored: string
): Promise<boolean> {
	/*
	 * Hardened password format.
	 */
	if (stored.startsWith('$argon2')) {
		try {
			return await argon2.verify(stored, password);
		} catch {
			return false;
		}
	}

	/*
	 * Legacy password format.
	 *
	 * Existing seeded accounts may still contain:
	 *
	 * sha256:<64 hexadecimal characters>
	 *
	 * Successful authentication will cause the hash to be
	 * upgraded to Argon2id by the login route.
	 */
	if (stored.startsWith('sha256:')) {
		return verifyLegacySha256(password, stored);
	}

	return false;
}

/*
 * Verify the original SHA-256 password format.
 *
 * This function exists only to allow a controlled migration
 * from the original challenge database.
 */
function verifyLegacySha256(
	password: string,
	stored: string
): boolean {
	const parts = stored.split(':');

	if (parts.length !== 2) {
		return false;
	}

	const [scheme, hash] = parts;

	if (scheme !== 'sha256' || !hash) {
		return false;
	}

	/*
	 * A SHA-256 digest is exactly 64 hexadecimal characters.
	 */
	if (!/^[0-9a-f]{64}$/i.test(hash)) {
		return false;
	}

	const actual = createHash('sha256')
		.update(password)
		.digest();

	const expected = Buffer.from(hash, 'hex');

	if (actual.length !== expected.length) {
		return false;
	}

	return timingSafeEqual(actual, expected);
}

/*
 * Determine whether the stored password is still using
 * the legacy SHA-256 format.
 */
export function needsPasswordUpgrade(
	stored: string
): boolean {
	return stored.startsWith('sha256:');
}