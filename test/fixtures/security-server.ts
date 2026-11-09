import { createApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import { openDatabase } from '../../src/database.js';

const database = openDatabase(':memory:');
const config = loadConfig({ jwtSecret: 'disposable-network-regression-secret-at-least32' });
const server = createApp(database, config).listen(0, '127.0.0.1', () => {
  process.send?.({ port: (server.address() as { port: number }).port });
});
process.on('message', message => {
  if (message === 'stop') {
    server.closeAllConnections();
    server.close(() => { database.close(); process.exit(0); });
  }
});
