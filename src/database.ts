import Database from 'better-sqlite3';
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

export type SqliteDatabase = Database.Database;

export function openDatabase(databasePath: string): SqliteDatabase {
  if (databasePath !== ':memory:') mkdirSync(path.dirname(path.resolve(databasePath)), { recursive: true });
  const database = new Database(databasePath);
  database.pragma('foreign_keys = ON');
  database.pragma('journal_mode = WAL');
  database.exec('CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)');
  database.transaction(() => {
    for (const name of ['001_init.sql', '002_security_limits.sql']) {
      if (database.prepare('SELECT 1 FROM schema_migrations WHERE name = ?').get(name)) continue;
      database.exec(readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8'));
      database.prepare('INSERT INTO schema_migrations(name) VALUES (?)').run(name);
    }
  })();
  return database;
}
