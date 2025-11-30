
import { app, BrowserWindow, ipcMain, dialog, clipboard } from 'electron';
import * as path from 'path';
import {
  isInitialized,
  initializeMasterPassword,
  verifyMasterPassword,
  lockVault,
  isVaultUnlocked,
  vaultStorage,
  generatePassword,
  logSecurityEvent,
  SecurityEvent,
  Outcome,
  logError,
  secureWipe,
  getCurrentSession,
} from '../core';

app.disableHardwareAcceleration();

let mainWindow: BrowserWindow | null = null;

let autoLockTimeout: NodeJS.Timeout | null = null;
const AUTO_LOCK_DELAY = 5 * 60 * 1000;

function resetAutoLockTimer(): void {
  if (autoLockTimeout) {
    clearTimeout(autoLockTimeout);
  }

  if (isVaultUnlocked()) {
    autoLockTimeout = setTimeout(() => {
      lockVault();
      mainWindow?.webContents.send('vault-locked');
      logSecurityEvent({
        event: SecurityEvent.SESSION_TIMEOUT,
        outcome: Outcome.SUCCESS,
        message: 'Vault auto-locked due to inactivity',
      });
    }, AUTO_LOCK_DELAY);
  }
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#0a0a0f',
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
    lockVault();
  });

  mainWindow.on('focus', resetAutoLockTimer);

  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }
}

app.whenReady().then(async () => {
  try {
    await vaultStorage.initialize();
  } catch (error) {
    logError('Failed to initialize storage', error as Error);
  }

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  lockVault();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('will-quit', () => {
  clipboard.clear();
  lockVault();
});


ipcMain.handle('vault:isInitialized', async () => {
  return isInitialized();
});

ipcMain.handle('vault:isUnlocked', async () => {
  return isVaultUnlocked();
});

ipcMain.handle('vault:init', async (_event, password: string) => {
  try {
    const result = await initializeMasterPassword(password);
    if (result.success) {
      resetAutoLockTimer();
    }
    return result;
  } catch (error) {
    logError('Failed to initialize vault', error as Error);
    return { success: false, message: 'Failed to initialize vault' };
  }
});

ipcMain.handle('vault:unlock', async (_event, password: string) => {
  try {
    const result = await verifyMasterPassword(password);
    if (result.success) {
      resetAutoLockTimer();
    }
    return result;
  } catch (error) {
    logError('Failed to unlock vault', error as Error);
    return { success: false, message: 'Failed to unlock vault' };
  }
});

ipcMain.handle('vault:lock', async () => {
  lockVault();
  if (autoLockTimeout) {
    clearTimeout(autoLockTimeout);
    autoLockTimeout = null;
  }
  return { success: true };
});

ipcMain.handle('credentials:list', async () => {
  try {
    resetAutoLockTimer();
    return { success: true, data: vaultStorage.listCredentials() };
  } catch (error) {
    return { success: false, message: 'Failed to list credentials' };
  }
});

ipcMain.handle('credentials:get', async (_event, id: string) => {
  try {
    resetAutoLockTimer();
    const credential = vaultStorage.getCredential(id);
    if (credential) {
      return { success: true, data: credential };
    }
    return { success: false, message: 'Credential not found' };
  } catch (error) {
    return { success: false, message: 'Failed to get credential' };
  }
});

ipcMain.handle('credentials:add', async (_event, data: {
  title: string;
  url?: string;
  username: string;
  password: string;
  notes?: string;
  category?: string;
}) => {
  try {
    resetAutoLockTimer();
    const credential = vaultStorage.addCredential(data);
    return { success: true, data: credential };
  } catch (error) {
    return { success: false, message: (error as Error).message };
  }
});

ipcMain.handle('credentials:update', async (_event, id: string, data: {
  title?: string;
  url?: string;
  username?: string;
  password?: string;
  notes?: string;
  category?: string;
}) => {
  try {
    resetAutoLockTimer();
    const credential = vaultStorage.updateCredential(id, data);
    if (credential) {
      return { success: true, data: credential };
    }
    return { success: false, message: 'Credential not found' };
  } catch (error) {
    return { success: false, message: (error as Error).message };
  }
});

ipcMain.handle('credentials:delete', async (_event, id: string) => {
  try {
    resetAutoLockTimer();
    const success = vaultStorage.deleteCredential(id);
    return { success, message: success ? 'Deleted' : 'Not found' };
  } catch (error) {
    return { success: false, message: 'Failed to delete credential' };
  }
});

ipcMain.handle('credentials:search', async (_event, query: string) => {
  try {
    resetAutoLockTimer();
    const results = vaultStorage.searchCredentials(query);
    return { success: true, data: results };
  } catch (error) {
    return { success: false, message: 'Search failed' };
  }
});

ipcMain.handle('credentials:categories', async () => {
  try {
    resetAutoLockTimer();
    return { success: true, data: vaultStorage.getCategories() };
  } catch (error) {
    return { success: false, message: 'Failed to get categories' };
  }
});

ipcMain.handle('password:generate', async (_event, length: number = 16, options?: {
  includeUppercase?: boolean;
  includeLowercase?: boolean;
  includeNumbers?: boolean;
  includeSymbols?: boolean;
}) => {
  try {
    const password = generatePassword(length, options);
    return { success: true, data: password };
  } catch (error) {
    return { success: false, message: 'Failed to generate password' };
  }
});

ipcMain.handle('clipboard:copy', async (_event, text: string) => {
  try {
    clipboard.writeText(text);

    setTimeout(() => {
      if (clipboard.readText() === text) {
        clipboard.clear();
      }
    }, 30000);

    return { success: true };
  } catch (error) {
    return { success: false, message: 'Failed to copy to clipboard' };
  }
});

ipcMain.handle('vault:stats', async () => {
  try {
    if (!isVaultUnlocked()) {
      return { success: false, message: 'Vault is locked' };
    }

    const count = vaultStorage.getCredentialCount();
    const categories = vaultStorage.getCategories();

    return {
      success: true,
      data: {
        credentialCount: count,
        categoryCount: categories.length,
        categories,
      },
    };
  } catch (error) {
    return { success: false, message: 'Failed to get stats' };
  }
});

ipcMain.handle('activity:ping', async () => {
  resetAutoLockTimer();
  return { success: true };
});

