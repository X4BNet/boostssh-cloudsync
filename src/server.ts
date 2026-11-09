import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { openDatabase } from './database.js';

const config = loadConfig();
const database = openDatabase(config.databasePath);
const port = Number(process.env.PORT ?? 3000);
const server = createApp(database, config).listen(port, '0.0.0.0', () => {
  console.log(`CloudSync listening on port ${port}`);
});

function shutdown() {
  server.close(() => {
    database.close();
    process.exit(0);
  });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
