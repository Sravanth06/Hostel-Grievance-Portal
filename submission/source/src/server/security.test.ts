import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from './app.ts';
import { openDatabase } from './db/connection.ts';
import { seedDatabase } from './db/seed.ts';

function cookieHeader(res: Response): string {
        const anyHeaders =
                res.headers as Headers & {
                        getSetCookie?: () => string[];
                };

        const list =
                anyHeaders.getSetCookie?.() ?? [];

        if (list.length > 0) {
                return list
                        .map((value) => value.split(';')[0])
                        .join('; ');
        }

        const raw = res.headers.get('set-cookie');

        return raw
                ? raw.split(';')[0]
                : '';
}

async function login(
        app: ReturnType<typeof createApp>,
        email: string,
        password: string
): Promise<string> {
        const res = await app.request(
                '/api/login',
                {
                        method: 'POST',
                        headers: {
                                'Content-Type':
                                        'application/json'
                        },
                        body: JSON.stringify({
                                email,
                                password
                        })
                }
        );

        expect(res.status).toBe(200);

        return cookieHeader(res);
}

describe(
        'HostelGrievance security controls',
        () => {
                let dir: string;
                let app: ReturnType<typeof createApp>;
                let db: ReturnType<typeof openDatabase>;

                beforeEach(() => {
                        dir = mkdtempSync(
                                join(
                                        tmpdir(),
                                        'hg-security-'
                                )
                        );

                        db = openDatabase(
                                join(
                                        dir,
                                        'hostel.db'
                                )
                        );

                        const uploadsDir =
                                join(
                                        dir,
                                        'uploads'
                                );

                        seedDatabase(
                                db,
                                uploadsDir
                        );

                        app = createApp({
                                db,
                                uploadsDir
                        });
                });

                afterEach(() => {
                        db.close();

                        rmSync(
                                dir,
                                {
                                        recursive: true,
                                        force: true
                                }
                        );
                });

                it(
                        'blocks unauthenticated grievance access',
                        async () => {
                                const res =
                                        await app.request(
                                                '/api/grievances/GRV-0001'
                                        );

                                expect(
                                        res.status
                                ).toBe(401);
                        }
                );

                it(
                        'enforces object-level authorization',
                        async () => {
                                const cookie =
                                        await login(
                                                app,
                                                'priya@example.test',
                                                'student123'
                                        );

                                const res =
                                        await app.request(
                                                '/api/grievances/GRV-0001',
                                                {
                                                        headers: {
                                                                Cookie: cookie
                                                        }
                                                }
                                        );

                                expect(
                                        res.status
                                ).toBe(403);
                        }
                );

                it(
                        'prevents students from changing grievance status',
                        async () => {
                                const cookie =
                                        await login(
                                                app,
                                                'student@example.test',
                                                'student123'
                                        );

                                const res =
                                        await app.request(
                                                '/api/grievances/GRV-0008',
                                                {
                                                        method: 'PATCH',
                                                        headers: {
                                                                'Content-Type':
                                                                        'application/json',
                                                                Cookie: cookie
                                                        },
                                                        body: JSON.stringify(
                                                                {
                                                                        status:
                                                                                'Resolved'
                                                                }
                                                        )
                                                }
                                        );

                                expect(
                                        res.status
                                ).toBe(403);
                        }
                );

                it(
                        'prevents one student from downloading another student attachment',
                        async () => {
                                const ownerCookie =
                                        await login(
                                                app,
                                                'student@example.test',
                                                'student123'
                                        );

                                const grievance =
                                        await app.request(
                                                '/api/grievances/GRV-0001',
                                                {
                                                        headers: {
                                                                Cookie: ownerCookie
                                                        }
                                                }
                                        );

                                expect(
                                        grievance.status
                                ).toBe(200);

                                const body =
                                        await grievance.json();

                                const attachmentId =
                                        body.data
                                                .attachments[0]
                                                .id;

                                const otherCookie =
                                        await login(
                                                app,
                                                'priya@example.test',
                                                'student123'
                                        );

                                const stolen =
                                        await app.request(
                                                `/api/attachments/${attachmentId}`,
                                                {
                                                        headers: {
                                                                Cookie: otherCookie
                                                        }
                                                }
                                        );

                                expect(
                                        stolen.status
                                ).toBe(403);
                        }
                );

                it(
                        'rejects attachment path traversal attempts',
                        async () => {
                                const cookie =
                                        await login(
                                                app,
                                                'student@example.test',
                                                'student123'
                                        );

                                const attempts = [
                                        '../../etc/passwd',
                                        '..%2F..%2Fetc%2Fpasswd',
                                        'foo/../../secret',
                                        'foo\\..\\secret'
                                ];

                                for (
                                        const id of attempts
                                ) {
                                        const res =
                                                await app.request(
                                                        `/api/attachments/${id}`,
                                                        {
                                                                headers: {
                                                                        Cookie: cookie
                                                                }
                                                        }
                                                );

                                        expect(
                                                res.status
                                        ).toBe(404);
                                }
                        }
                );

                it(
                        'invalidates a session after logout',
                        async () => {
                                const cookie =
                                        await login(
                                                app,
                                                'student@example.test',
                                                'student123'
                                        );

                                const before =
                                        await app.request(
                                                '/api/me',
                                                {
                                                        headers: {
                                                                Cookie: cookie
                                                        }
                                                }
                                        );

                                expect(
                                        before.status
                                ).toBe(200);

                                const logout =
                                        await app.request(
                                                '/api/logout',
                                                {
                                                        method: 'POST',
                                                        headers: {
                                                                Cookie: cookie
                                                        }
                                                }
                                        );

                                expect(
                                        logout.status
                                ).toBe(200);

                                const after =
                                        await app.request(
                                                '/api/me',
                                                {
                                                        headers: {
                                                                Cookie: cookie
                                                        }
                                                }
                                        );

                                expect(
                                        after.status
                                ).toBe(401);
                        }
                );

                it(
                        'sets security-related session cookie attributes',
                        async () => {
                                const res =
                                        await app.request(
                                                '/api/login',
                                                {
                                                        method: 'POST',
                                                        headers: {
                                                                'Content-Type':
                                                                        'application/json'
                                                        },
                                                        body: JSON.stringify(
                                                                {
                                                                        email:
                                                                                'student@example.test',
                                                                        password:
                                                                                'student123'
                                                                }
                                                        )
                                                }
                                        );

                                expect(
                                        res.status
                                ).toBe(200);

                                const setCookie =
                                        res.headers.get(
                                                'set-cookie'
                                        ) ?? '';

                                expect(
                                        setCookie
                                ).toContain(
                                        'HttpOnly'
                                );

                                expect(
                                        setCookie.toLowerCase()
                                ).toContain(
                                        'samesite=lax'
                                );
                        }
                );

                it(
                        'does not expose password fields through the API',
                        async () => {
                                const cookie =
                                        await login(
                                                app,
                                                'student@example.test',
                                                'student123'
                                        );

                                const res =
                                        await app.request(
                                                '/api/me',
                                                {
                                                        headers: {
                                                                Cookie: cookie
                                                        }
                                                }
                                        );

                                expect(
                                        res.status
                                ).toBe(200);

                                const json =
                                        await res.json();

                                expect(
                                        json.user.password
                                ).toBeUndefined();

                                expect(
                                        json.user.password_hash
                                ).toBeUndefined();
                        }
                );
        }
);