
export {
  secureWipe,
  secureWipeMultiple,
  stringToSecureBuffer,
  bufferToStringAndWipe,
  SecureBuffer,
  withSecureBuffer,
  secureCompare,
} from './memory';

export {
  generateSalt,
  generateIV,
  deriveKey,
  deriveKeySync,
  encryptData,
  decryptData,
  encryptWithPassword,
  decryptWithPassword,
  generatePassword,
  isValidKey,
  getEncryptionConfig,
  EncryptedData,
} from './crypto';

export {
  isInitialized,
  validatePasswordStrength,
  initializeMasterPassword,
  verifyMasterPassword,
  changeMasterPassword,
  getCurrentSession,
  lockVault,
  isVaultUnlocked,
  AuthResult,
} from './auth';

export {
  vaultStorage,
  VaultStorage,
  Credential,
  CreateCredentialInput,
  UpdateCredentialInput,
  CredentialListItem,
} from './storage';

export {
  logSecurityEvent,
  logInfo,
  logWarning,
  logError,
  logDebug,
  toUserSafeError,
  UserFacingError,
  withSecureErrorHandling,
  SecurityEvent,
  Outcome,
  logger,
} from './logger';

