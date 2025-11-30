
import * as crypto from 'crypto';
import { secureWipe } from './memory';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const SALT_LENGTH = 32;

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

export interface EncryptedData {
  ciphertext: string;
  iv: string;
  authTag: string;
  salt?: string;
}

export function generateSalt(length: number = SALT_LENGTH): Buffer {
  return crypto.randomBytes(length);
}

export function generateIV(): Buffer {
  return crypto.randomBytes(IV_LENGTH);
}

export async function deriveKey(password: Buffer, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      KEY_LENGTH,
      {
        N: SCRYPT_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
      },
      (err, derivedKey) => {
        if (err) {
          reject(err);
        } else {
          resolve(derivedKey);
        }
      }
    );
  });
}

export function deriveKeySync(password: Buffer, salt: Buffer): Buffer {
  return crypto.scryptSync(password, salt, KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
}

export function encryptData(data: Buffer, key: Buffer): EncryptedData {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`Invalid key length. Expected ${KEY_LENGTH} bytes, got ${key.length}`);
  }

  const iv = generateIV();

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

export function decryptData(encrypted: EncryptedData, key: Buffer): Buffer {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`Invalid key length. Expected ${KEY_LENGTH} bytes, got ${key.length}`);
  }

  const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
  const iv = Buffer.from(encrypted.iv, 'base64');
  const authTag = Buffer.from(encrypted.authTag, 'base64');

  if (iv.length !== IV_LENGTH) {
    throw new Error(`Invalid IV length. Expected ${IV_LENGTH} bytes, got ${iv.length}`);
  }

  if (authTag.length !== AUTH_TAG_LENGTH) {
    throw new Error(`Invalid auth tag length. Expected ${AUTH_TAG_LENGTH} bytes, got ${authTag.length}`);
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted;
  } catch (error) {
    throw new Error('Decryption failed: Invalid key or corrupted data');
  }
}

export async function encryptWithPassword(data: Buffer, password: Buffer): Promise<EncryptedData> {
  const salt = generateSalt();
  const key = await deriveKey(password, salt);

  try {
    const encrypted = encryptData(data, key);
    encrypted.salt = salt.toString('base64');
    return encrypted;
  } finally {
    secureWipe(key);
  }
}

export async function decryptWithPassword(encrypted: EncryptedData, password: Buffer): Promise<Buffer> {
  if (!encrypted.salt) {
    throw new Error('Encrypted data does not contain salt');
  }

  const salt = Buffer.from(encrypted.salt, 'base64');
  const key = await deriveKey(password, salt);

  try {
    return decryptData(encrypted, key);
  } finally {
    secureWipe(key);
  }
}

export function generatePassword(
  length: number = 16,
  options: {
    includeUppercase?: boolean;
    includeLowercase?: boolean;
    includeNumbers?: boolean;
    includeSymbols?: boolean;
  } = {}
): string {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSymbols = true,
  } = options;

  let charset = '';
  if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (includeNumbers) charset += '0123456789';
  if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (charset.length === 0) {
    throw new Error('At least one character set must be selected');
  }

  const randomBytes = crypto.randomBytes(length);
  let password = '';

  for (let i = 0; i < length; i++) {
    password += charset[randomBytes[i] % charset.length];
  }

  return password;
}

export function isValidKey(key: Buffer): boolean {
  return Buffer.isBuffer(key) && key.length === KEY_LENGTH;
}

export function getEncryptionConfig(): {
  algorithm: string;
  keyLength: number;
  ivLength: number;
  authTagLength: number;
  kdfAlgorithm: string;
  kdfIterations: number;
} {
  return {
    algorithm: ALGORITHM,
    keyLength: KEY_LENGTH,
    ivLength: IV_LENGTH,
    authTagLength: AUTH_TAG_LENGTH,
    kdfAlgorithm: 'scrypt',
    kdfIterations: SCRYPT_N,
  };
}

