import initSqlJs, { Database as SqlJsDatabase, QueryExecResult } from 'sql.js';
import * as path from 'path';
import * as fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { encryptData, decryptData, EncryptedData } from './crypto';
import { secureWipe, stringToSecureBuffer } from './memory';
import { logSecurityEvent, SecurityEvent, Outcome, logError } from './logger';
import { getCurrentSession } from './auth';

const DATA_DIR = process.env.DB_PATH
  ? path.dirname(process.env.DB_PATH)
  : path.join(process.cwd(), '.vault');
const DB_FILE = process.env.DB_PATH || path.join(DATA_DIR, 'vault.db');

export interface Credential {
  id: string;
  title: string;
  url: string;
  username: string;
  password: string;
  notes: string;
  category: string;
  ownerId: string;
  createdAt: string;
  updatedAt: string;
}

interface EncryptedCredential {
  id: string;
  title: string;
  url: string;
  username: string;
  encryptedPassword: string;
  iv: string;
  authTag: string;
  notes: string;
  category: string;
  ownerId: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateCredentialInput {
  title: string;
  url?: string;
  username: string;
  password: string;
  notes?: string;
  category?: string;
}

export interface UpdateCredentialInput {
  title?: string;
  url?: string;
  username?: string;
  password?: string;
  notes?: string;
  category?: string;
}

export interface CredentialListItem {
  id: string;
  title: string;
  url: string;
  username: string;
  category: string;
  createdAt: string;
  updatedAt: string;
}

type SqlValue = string | number | Uint8Array | null;

function rowToObject(columns: string[], values: SqlValue[]): Record<string, SqlValue> {
  const row: Record<string, SqlValue> = {};
  columns.forEach((col: string, i: number) => {
    row[col] = values[i];
  });
  return row;
}

class VaultStorage {
  private db: SqlJsDatabase | null = null;
  private initialized: boolean = false;
  private SQL: ReturnType<typeof initSqlJs> extends Promise<infer T> ? T : never = null as any;

  private ensureDataDir(): void {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    }
  }

  private saveDatabase(): void {
    if (this.db) {
      this.ensureDataDir();
      const data = this.db.export();
      const buffer = Buffer.from(data);
      fs.writeFileSync(DB_FILE, buffer, { mode: 0o600 });
    }
  }

  async initialize(): Promise<void> {
    if (this.initialized && this.db) {
      return;
    }

    this.ensureDataDir();

    this.SQL = await initSqlJs();

    if (fs.existsSync(DB_FILE)) {
      const buffer = fs.readFileSync(DB_FILE);
      this.db = new this.SQL.Database(buffer);
    } else {
      this.db = new this.SQL.Database();
    }

    this.db.run(`
      CREATE TABLE IF NOT EXISTS credentials (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        url TEXT DEFAULT '',
        username TEXT NOT NULL,
        encryptedPassword TEXT NOT NULL,
        iv TEXT NOT NULL,
        authTag TEXT NOT NULL,
        notes TEXT DEFAULT '',
        category TEXT DEFAULT 'General',
        ownerId TEXT NOT NULL,
        createdAt TEXT NOT NULL,
        updatedAt TEXT NOT NULL
      )
    `);

    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_credentials_owner
      ON credentials(ownerId)
    `);

    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_credentials_category
      ON credentials(category, ownerId)
    `);

    this.saveDatabase();
    this.initialized = true;
  }

  private ensureInitialized(): void {
    if (!this.initialized || !this.db) {
      throw new Error('Database not initialized. Call initialize() first.');
    }
  }

  close(): void {
    if (this.db) {
      this.saveDatabase();
      this.db.close();
      this.db = null;
      this.initialized = false;
    }
  }

  private getAuthenticatedSession(): { userId: string; sessionId: string; derivedKey: Buffer } {
    const session = getCurrentSession();
    if (!session) {
      throw new Error('Not authenticated. Please unlock the vault first.');
    }
    return session;
  }

  private validateInput(input: Record<string, unknown>): void {
    for (const [key, value] of Object.entries(input)) {
      if (value === undefined || value === null) continue;

      if (typeof value === 'string') {
        if (value.length > 10000) {
          throw new Error(`${key} exceeds maximum length`);
        }
      }
    }
  }

  addCredential(input: CreateCredentialInput): CredentialListItem {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    this.validateInput(input as unknown as Record<string, unknown>);

    if (!input.title || input.title.trim().length === 0) {
      throw new Error('Title is required');
    }

    if (!input.username || input.username.trim().length === 0) {
      throw new Error('Username is required');
    }

    if (!input.password || input.password.length === 0) {
      throw new Error('Password is required');
    }

    const passwordBuffer = stringToSecureBuffer(input.password);

    try {
      const encrypted = encryptData(passwordBuffer, session.derivedKey);

      const id = uuidv4();
      const now = new Date().toISOString();

      const credential: EncryptedCredential = {
        id,
        title: input.title.trim(),
        url: input.url?.trim() || '',
        username: input.username.trim(),
        encryptedPassword: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        notes: input.notes?.trim() || '',
        category: input.category?.trim() || 'General',
        ownerId: session.userId,
        createdAt: now,
        updatedAt: now,
      };

      this.db!.run(`
        INSERT INTO credentials (
          id, title, url, username, encryptedPassword, iv, authTag,
          notes, category, ownerId, createdAt, updatedAt
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        credential.id,
        credential.title,
        credential.url,
        credential.username,
        credential.encryptedPassword,
        credential.iv,
        credential.authTag,
        credential.notes,
        credential.category,
        credential.ownerId,
        credential.createdAt,
        credential.updatedAt,
      ]);

      this.saveDatabase();

      logSecurityEvent({
        event: SecurityEvent.RECORD_ADDED,
        userId: session.userId,
        sessionId: session.sessionId,
        outcome: Outcome.SUCCESS,
        message: 'Credential added',
        metadata: { credentialId: id, title: credential.title },
      });

      return {
        id,
        title: credential.title,
        url: credential.url,
        username: credential.username,
        category: credential.category,
        createdAt: credential.createdAt,
        updatedAt: credential.updatedAt,
      };
    } finally {
      secureWipe(passwordBuffer);
    }
  }

  getCredential(id: string): Credential | null {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const result = this.db!.exec(`
      SELECT * FROM credentials WHERE id = ? AND ownerId = ?
    `, [id, session.userId]);

    if (result.length === 0 || result[0].values.length === 0) {
      return null;
    }

    const columns = result[0].columns;
    const values = result[0].values[0];
    const row = rowToObject(columns, values);

    const encrypted: EncryptedData = {
      ciphertext: row.encryptedPassword as string,
      iv: row.iv as string,
      authTag: row.authTag as string,
    };

    const decryptedPassword = decryptData(encrypted, session.derivedKey);
    const password = decryptedPassword.toString('utf8');

    secureWipe(decryptedPassword);

    logSecurityEvent({
      event: SecurityEvent.RECORD_VIEWED,
      userId: session.userId,
      sessionId: session.sessionId,
      outcome: Outcome.SUCCESS,
      message: 'Credential viewed',
      metadata: { credentialId: id },
    });

    return {
      id: row.id as string,
      title: row.title as string,
      url: row.url as string,
      username: row.username as string,
      password,
      notes: row.notes as string,
      category: row.category as string,
      ownerId: row.ownerId as string,
      createdAt: row.createdAt as string,
      updatedAt: row.updatedAt as string,
    };
  }

  listCredentials(): CredentialListItem[] {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const result = this.db!.exec(`
      SELECT id, title, url, username, category, createdAt, updatedAt
      FROM credentials
      WHERE ownerId = ?
      ORDER BY updatedAt DESC
    `, [session.userId]);

    if (result.length === 0) {
      return [];
    }

    const columns = result[0].columns;
    return result[0].values.map((values: SqlValue[]) => {
      const row = rowToObject(columns, values);
      return row as unknown as CredentialListItem;
    });
  }

  listCredentialsByCategory(category: string): CredentialListItem[] {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const result = this.db!.exec(`
      SELECT id, title, url, username, category, createdAt, updatedAt
      FROM credentials
      WHERE ownerId = ? AND category = ?
      ORDER BY updatedAt DESC
    `, [session.userId, category]);

    if (result.length === 0) {
      return [];
    }

    const columns = result[0].columns;
    return result[0].values.map((values: SqlValue[]) => {
      const row = rowToObject(columns, values);
      return row as unknown as CredentialListItem;
    });
  }

  searchCredentials(query: string): CredentialListItem[] {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const sanitizedQuery = `%${query.replace(/[%_]/g, '\\$&')}%`;

    const result = this.db!.exec(`
      SELECT id, title, url, username, category, createdAt, updatedAt
      FROM credentials
      WHERE ownerId = ? AND (
        title LIKE ? ESCAPE '\\' OR
        username LIKE ? ESCAPE '\\' OR
        url LIKE ? ESCAPE '\\'
      )
      ORDER BY updatedAt DESC
    `, [session.userId, sanitizedQuery, sanitizedQuery, sanitizedQuery]);

    if (result.length === 0) {
      return [];
    }

    const columns = result[0].columns;
    return result[0].values.map((values: SqlValue[]) => {
      const row = rowToObject(columns, values);
      return row as unknown as CredentialListItem;
    });
  }

  updateCredential(id: string, input: UpdateCredentialInput): CredentialListItem | null {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    this.validateInput(input as unknown as Record<string, unknown>);

    const existingResult = this.db!.exec(`
      SELECT * FROM credentials WHERE id = ? AND ownerId = ?
    `, [id, session.userId]);

    if (existingResult.length === 0 || existingResult[0].values.length === 0) {
      logSecurityEvent({
        event: SecurityEvent.ACCESS_DENIED,
        userId: session.userId,
        sessionId: session.sessionId,
        outcome: Outcome.DENIED,
        message: 'Attempted to update non-existent or unauthorized credential',
        metadata: { credentialId: id },
      });
      return null;
    }

    const updates: string[] = [];
    const values: (string | number)[] = [];

    if (input.title !== undefined) {
      updates.push('title = ?');
      values.push(input.title.trim());
    }

    if (input.url !== undefined) {
      updates.push('url = ?');
      values.push(input.url.trim());
    }

    if (input.username !== undefined) {
      updates.push('username = ?');
      values.push(input.username.trim());
    }

    if (input.notes !== undefined) {
      updates.push('notes = ?');
      values.push(input.notes.trim());
    }

    if (input.category !== undefined) {
      updates.push('category = ?');
      values.push(input.category.trim());
    }

    let passwordBuffer: Buffer | null = null;
    if (input.password !== undefined) {
      passwordBuffer = stringToSecureBuffer(input.password);
      const encrypted = encryptData(passwordBuffer, session.derivedKey);
      updates.push('encryptedPassword = ?');
      updates.push('iv = ?');
      updates.push('authTag = ?');
      values.push(encrypted.ciphertext);
      values.push(encrypted.iv);
      values.push(encrypted.authTag);
    }

    try {
      updates.push('updatedAt = ?');
      values.push(new Date().toISOString());

      values.push(id);
      values.push(session.userId);

      this.db!.run(`
        UPDATE credentials
        SET ${updates.join(', ')}
        WHERE id = ? AND ownerId = ?
      `, values);

      this.saveDatabase();

      logSecurityEvent({
        event: SecurityEvent.RECORD_UPDATED,
        userId: session.userId,
        sessionId: session.sessionId,
        outcome: Outcome.SUCCESS,
        message: 'Credential updated',
        metadata: { credentialId: id },
      });

      const result = this.db!.exec(`
        SELECT id, title, url, username, category, createdAt, updatedAt
        FROM credentials WHERE id = ?
      `, [id]);

      if (result.length === 0 || result[0].values.length === 0) {
        return null;
      }

      const columns = result[0].columns;
      const rowValues = result[0].values[0];
      const row = rowToObject(columns, rowValues);

      return row as unknown as CredentialListItem;
    } finally {
      if (passwordBuffer) {
        secureWipe(passwordBuffer);
      }
    }
  }

  deleteCredential(id: string): boolean {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const existingResult = this.db!.exec(`
      SELECT id FROM credentials WHERE id = ? AND ownerId = ?
    `, [id, session.userId]);

    if (existingResult.length === 0 || existingResult[0].values.length === 0) {
      logSecurityEvent({
        event: SecurityEvent.ACCESS_DENIED,
        userId: session.userId,
        sessionId: session.sessionId,
        outcome: Outcome.DENIED,
        message: 'Attempted to delete non-existent or unauthorized credential',
        metadata: { credentialId: id },
      });
      return false;
    }

    this.db!.run(`
      DELETE FROM credentials WHERE id = ? AND ownerId = ?
    `, [id, session.userId]);

    this.saveDatabase();

    logSecurityEvent({
      event: SecurityEvent.RECORD_DELETED,
      userId: session.userId,
      sessionId: session.sessionId,
      outcome: Outcome.SUCCESS,
      message: 'Credential deleted',
      metadata: { credentialId: id },
    });

    return true;
  }

  getCategories(): string[] {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const result = this.db!.exec(`
      SELECT DISTINCT category FROM credentials
      WHERE ownerId = ?
      ORDER BY category
    `, [session.userId]);

    if (result.length === 0) {
      return [];
    }

    return result[0].values.map((row: SqlValue[]) => row[0] as string);
  }

  getCredentialCount(): number {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const result = this.db!.exec(`
      SELECT COUNT(*) as count FROM credentials WHERE ownerId = ?
    `, [session.userId]);

    if (result.length === 0 || result[0].values.length === 0) {
      return 0;
    }

    return result[0].values[0][0] as number;
  }

  async reEncryptAllCredentials(oldKey: Buffer, newKey: Buffer): Promise<void> {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const result = this.db!.exec(`
      SELECT * FROM credentials WHERE ownerId = ?
    `, [session.userId]);

    if (result.length === 0) {
      return;
    }

    const columns = result[0].columns;
    const credentials = result[0].values.map((values: SqlValue[]) => {
      const row = rowToObject(columns, values);
      return row as unknown as EncryptedCredential;
    });

    for (const cred of credentials) {
      const encrypted: EncryptedData = {
        ciphertext: cred.encryptedPassword,
        iv: cred.iv,
        authTag: cred.authTag,
      };

      const decrypted = decryptData(encrypted, oldKey);

      try {
        const newEncrypted = encryptData(decrypted, newKey);

        this.db!.run(`
          UPDATE credentials
          SET encryptedPassword = ?, iv = ?, authTag = ?, updatedAt = ?
          WHERE id = ? AND ownerId = ?
        `, [
          newEncrypted.ciphertext,
          newEncrypted.iv,
          newEncrypted.authTag,
          new Date().toISOString(),
          cred.id,
          session.userId,
        ]);
      } finally {
        secureWipe(decrypted);
      }
    }

    this.saveDatabase();

    logSecurityEvent({
      event: SecurityEvent.MASTER_PASSWORD_CHANGED,
      userId: session.userId,
      sessionId: session.sessionId,
      outcome: Outcome.SUCCESS,
      message: 'All credentials re-encrypted with new key',
      metadata: { count: credentials.length },
    });
  }
}

export const vaultStorage = new VaultStorage();

export { VaultStorage };
