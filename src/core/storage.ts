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
        url TEXT NOT NULL,
        username TEXT NOT NULL,
        encryptedPassword TEXT NOT NULL,
        iv TEXT NOT NULL,
        authTag TEXT NOT NULL,
        notes TEXT NOT NULL,
        category TEXT NOT NULL,
        ownerId TEXT NOT NULL,
        createdAt TEXT NOT NULL,
        updatedAt TEXT NOT NULL,
        title_iv TEXT,
        title_tag TEXT,
        url_iv TEXT,
        url_tag TEXT,
        username_iv TEXT,
        username_tag TEXT,
        notes_iv TEXT,
        notes_tag TEXT,
        category_iv TEXT,
        category_tag TEXT
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

    const columns = this.db.exec(`PRAGMA table_info(credentials)`)[0]?.values?.map(v => v[1]) || [];
    const required = [
      'title_iv','title_tag','url_iv','url_tag','username_iv','username_tag','notes_iv','notes_tag','category_iv','category_tag'
    ];
    for (const col of required) {
      if (!columns.includes(col)) {
        this.db.run(`ALTER TABLE credentials ADD COLUMN ${col} TEXT`);
      }
    }

    try {
      const session = getCurrentSession();
      if (session) {
        const result = this.db.exec(`SELECT * FROM credentials`);
        if (result.length > 0) {
          const columns = result[0].columns;
          for (const values of result[0].values) {
            const row = rowToObject(columns, values);
            if (!row.title_iv || !row.title_tag) {
              const encTitle = encryptData(stringToSecureBuffer(row.title as string), session.derivedKey);
              const encUrl = encryptData(stringToSecureBuffer(row.url as string), session.derivedKey);
              const encUsername = encryptData(stringToSecureBuffer(row.username as string), session.derivedKey);
              const encNotes = encryptData(stringToSecureBuffer(row.notes as string), session.derivedKey);
              const encCategory = encryptData(stringToSecureBuffer(row.category as string), session.derivedKey);
              this.db.run(`UPDATE credentials SET
                title = ?, title_iv = ?, title_tag = ?,
                url = ?, url_iv = ?, url_tag = ?,
                username = ?, username_iv = ?, username_tag = ?,
                notes = ?, notes_iv = ?, notes_tag = ?,
                category = ?, category_iv = ?, category_tag = ?
                WHERE id = ?
              `,[
                encTitle.ciphertext, encTitle.iv, encTitle.authTag,
                encUrl.ciphertext, encUrl.iv, encUrl.authTag,
                encUsername.ciphertext, encUsername.iv, encUsername.authTag,
                encNotes.ciphertext, encNotes.iv, encNotes.authTag,
                encCategory.ciphertext, encCategory.iv, encCategory.authTag,
                row.id
              ]);
            }
          }
        }
      }
    } catch {}
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

    const titleBuffer = stringToSecureBuffer(input.title.trim());
    const urlBuffer = stringToSecureBuffer(input.url?.trim() || '');
    const usernameBuffer = stringToSecureBuffer(input.username.trim());
    const passwordBuffer = stringToSecureBuffer(input.password);
    const notesBuffer = stringToSecureBuffer(input.notes?.trim() || '');
    const categoryBuffer = stringToSecureBuffer(input.category?.trim() || 'General');

    try {
      const encTitle = encryptData(titleBuffer, session.derivedKey);
      const encUrl = encryptData(urlBuffer, session.derivedKey);
      const encUsername = encryptData(usernameBuffer, session.derivedKey);
      const encPassword = encryptData(passwordBuffer, session.derivedKey);
      const encNotes = encryptData(notesBuffer, session.derivedKey);
      const encCategory = encryptData(categoryBuffer, session.derivedKey);

      const id = uuidv4();
      const now = new Date().toISOString();

      this.db!.run(`
        INSERT INTO credentials (
          id, title, url, username, encryptedPassword, iv, authTag,
          notes, category, ownerId, createdAt, updatedAt,
          title_iv, title_tag, url_iv, url_tag, username_iv, username_tag, notes_iv, notes_tag, category_iv, category_tag
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        id,
        encTitle.ciphertext,
        encUrl.ciphertext,
        encUsername.ciphertext,
        encPassword.ciphertext,
        encPassword.iv,
        encPassword.authTag,
        encNotes.ciphertext,
        encCategory.ciphertext,
        session.userId,
        now,
        now,
        encTitle.iv,
        encTitle.authTag,
        encUrl.iv,
        encUrl.authTag,
        encUsername.iv,
        encUsername.authTag,
        encNotes.iv,
        encNotes.authTag,
        encCategory.iv,
        encCategory.authTag
      ]);

      this.saveDatabase();

      logSecurityEvent({
        event: SecurityEvent.RECORD_ADDED,
        userId: session.userId,
        sessionId: session.sessionId,
        outcome: Outcome.SUCCESS,
        message: 'Credential added',
        metadata: { credentialId: id },
      });

      return {
        id,
        title: input.title.trim(),
        url: input.url?.trim() || '',
        username: input.username.trim(),
        category: input.category?.trim() || 'General',
        createdAt: now,
        updatedAt: now,
      };
    } finally {
      secureWipe(titleBuffer);
      secureWipe(urlBuffer);
      secureWipe(usernameBuffer);
      secureWipe(passwordBuffer);
      secureWipe(notesBuffer);
      secureWipe(categoryBuffer);
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

    const decTitle = decryptData({ciphertext: row.title as string, iv: row.title_iv as string, authTag: row.title_tag as string}, session.derivedKey).toString('utf8');
    const decUrl = decryptData({ciphertext: row.url as string, iv: row.url_iv as string, authTag: row.url_tag as string}, session.derivedKey).toString('utf8');
    const decUsername = decryptData({ciphertext: row.username as string, iv: row.username_iv as string, authTag: row.username_tag as string}, session.derivedKey).toString('utf8');
    const decPassword = decryptData({ciphertext: row.encryptedPassword as string, iv: row.iv as string, authTag: row.authTag as string}, session.derivedKey).toString('utf8');
    const decNotes = decryptData({ciphertext: row.notes as string, iv: row.notes_iv as string, authTag: row.notes_tag as string}, session.derivedKey).toString('utf8');
    const decCategory = decryptData({ciphertext: row.category as string, iv: row.category_iv as string, authTag: row.category_tag as string}, session.derivedKey).toString('utf8');

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
      title: decTitle,
      url: decUrl,
      username: decUsername,
      password: decPassword,
      notes: decNotes,
      category: decCategory,
      ownerId: row.ownerId as string,
      createdAt: row.createdAt as string,
      updatedAt: row.updatedAt as string,
    };
  }

  listCredentials(): CredentialListItem[] {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const result = this.db!.exec(`
      SELECT id, title, title_iv, title_tag, url, url_iv, url_tag, username, username_iv, username_tag, category, category_iv, category_tag, createdAt, updatedAt
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
      try {
        const decTitle = decryptData({ciphertext: row.title as string, iv: row.title_iv as string, authTag: row.title_tag as string}, session.derivedKey).toString('utf8');
        const decUrl = decryptData({ciphertext: row.url as string, iv: row.url_iv as string, authTag: row.url_tag as string}, session.derivedKey).toString('utf8');
        const decUsername = decryptData({ciphertext: row.username as string, iv: row.username_iv as string, authTag: row.username_tag as string}, session.derivedKey).toString('utf8');
        const decCategory = decryptData({ciphertext: row.category as string, iv: row.category_iv as string, authTag: row.category_tag as string}, session.derivedKey).toString('utf8');
        return {
          id: row.id as string,
          title: decTitle,
          url: decUrl,
          username: decUsername,
          category: decCategory,
          createdAt: row.createdAt as string,
          updatedAt: row.updatedAt as string,
        };
      } catch (error) {
        logError('Failed to decrypt credential in list', error as Error);
        return row as unknown as CredentialListItem;
      }
    });
  }

  listCredentialsByCategory(category: string): CredentialListItem[] {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const result = this.db!.exec(`
      SELECT id, title, title_iv, title_tag, url, url_iv, url_tag, username, username_iv, username_tag, category, category_iv, category_tag, createdAt, updatedAt
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
      try {
        const decTitle = decryptData({ciphertext: row.title as string, iv: row.title_iv as string, authTag: row.title_tag as string}, session.derivedKey).toString('utf8');
        const decUrl = decryptData({ciphertext: row.url as string, iv: row.url_iv as string, authTag: row.url_tag as string}, session.derivedKey).toString('utf8');
        const decUsername = decryptData({ciphertext: row.username as string, iv: row.username_iv as string, authTag: row.username_tag as string}, session.derivedKey).toString('utf8');
        const decCategory = decryptData({ciphertext: row.category as string, iv: row.category_iv as string, authTag: row.category_tag as string}, session.derivedKey).toString('utf8');
        
        if (decCategory.toLowerCase() === category.toLowerCase()) {
          return {
            id: row.id as string,
            title: decTitle,
            url: decUrl,
            username: decUsername,
            category: decCategory,
            createdAt: row.createdAt as string,
            updatedAt: row.updatedAt as string,
          };
        }
        return null;
      } catch (error) {
        logError('Failed to decrypt credential in category list', error as Error);
        return null;
      }
    }).filter(Boolean) as CredentialListItem[];
  }

  searchCredentials(query: string): CredentialListItem[] {
    this.ensureInitialized();
    const session = this.getAuthenticatedSession();

    const result = this.db!.exec(`
      SELECT id, title, title_iv, title_tag, url, url_iv, url_tag, username, username_iv, username_tag, category, category_iv, category_tag, createdAt, updatedAt
      FROM credentials
      WHERE ownerId = ?
      ORDER BY updatedAt DESC
    `, [session.userId]);

    if (result.length === 0) {
      return [];
    }

    const columns = result[0].columns;
    const lowerQuery = query.toLowerCase();
    return result[0].values
      .map((values: SqlValue[]) => {
        const row = rowToObject(columns, values);
        try {
          const decTitle = decryptData({ciphertext: row.title as string, iv: row.title_iv as string, authTag: row.title_tag as string}, session.derivedKey).toString('utf8');
          const decUrl = decryptData({ciphertext: row.url as string, iv: row.url_iv as string, authTag: row.url_tag as string}, session.derivedKey).toString('utf8');
          const decUsername = decryptData({ciphertext: row.username as string, iv: row.username_iv as string, authTag: row.username_tag as string}, session.derivedKey).toString('utf8');
          const decCategory = decryptData({ciphertext: row.category as string, iv: row.category_iv as string, authTag: row.category_tag as string}, session.derivedKey).toString('utf8');
          return {
            id: row.id as string,
            title: decTitle,
            url: decUrl,
            username: decUsername,
            category: decCategory,
            createdAt: row.createdAt as string,
            updatedAt: row.updatedAt as string,
          };
        } catch (error) {
          logError('Failed to decrypt credential in search', error as Error);
          return null;
        }
      })
      .filter((cred): cred is CredentialListItem => 
        cred !== null && (
          cred.title.toLowerCase().includes(lowerQuery) ||
          cred.username.toLowerCase().includes(lowerQuery) ||
          cred.url.toLowerCase().includes(lowerQuery)
        )
      );
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
