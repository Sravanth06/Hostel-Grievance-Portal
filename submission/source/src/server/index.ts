import { serve } from '@hono/node-server';

import { createApp } from './app.ts';
import {
        API_PORT,
        DEFAULT_DB_PATH,
        DEFAULT_UPLOADS_DIR
} from './config.ts';

import { openDatabase } from './db/connection.ts';

async function main(): Promise<void> {
        const db = openDatabase(DEFAULT_DB_PATH);

        const app = createApp({
                db,
                uploadsDir: DEFAULT_UPLOADS_DIR
        });

        console.log(
                `HostelGrievance API running on port ${API_PORT}`
        );

        serve({
                fetch: app.fetch,
                port: API_PORT
        });
}

main().catch((error) => {
        console.error(
                'Failed to start server:',
                error
        );

        process.exit(1);
});