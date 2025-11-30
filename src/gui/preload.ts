
import { contextBridge, ipcRenderer } from 'electron';

const api = {
  vault: {
    isInitialized: (): Promise<boolean> =>
      ipcRenderer.invoke('vault:isInitialized'),

    isUnlocked: (): Promise<boolean> =>
      ipcRenderer.invoke('vault:isUnlocked'),

    init: (password: string): Promise<{ success: boolean; message?: string }> =>
      ipcRenderer.invoke('vault:init', password),

    unlock: (password: string): Promise<{ success: boolean; message?: string }> =>
      ipcRenderer.invoke('vault:unlock', password),

    lock: (): Promise<{ success: boolean }> =>
      ipcRenderer.invoke('vault:lock'),

    stats: (): Promise<{ success: boolean; data?: { credentialCount: number; categoryCount: number; categories: string[] } }> =>
      ipcRenderer.invoke('vault:stats'),

    onLocked: (callback: () => void) => {
      ipcRenderer.on('vault-locked', callback);
      return () => ipcRenderer.removeListener('vault-locked', callback);
    },
  },

  credentials: {
    list: (): Promise<{ success: boolean; data?: Array<{
      id: string;
      title: string;
      url: string;
      username: string;
      category: string;
      createdAt: string;
      updatedAt: string;
    }> }> =>
      ipcRenderer.invoke('credentials:list'),

    get: (id: string): Promise<{ success: boolean; data?: {
      id: string;
      title: string;
      url: string;
      username: string;
      password: string;
      notes: string;
      category: string;
      createdAt: string;
      updatedAt: string;
    }; message?: string }> =>
      ipcRenderer.invoke('credentials:get', id),

    add: (data: {
      title: string;
      url?: string;
      username: string;
      password: string;
      notes?: string;
      category?: string;
    }): Promise<{ success: boolean; data?: { id: string }; message?: string }> =>
      ipcRenderer.invoke('credentials:add', data),

    update: (id: string, data: {
      title?: string;
      url?: string;
      username?: string;
      password?: string;
      notes?: string;
      category?: string;
    }): Promise<{ success: boolean; message?: string }> =>
      ipcRenderer.invoke('credentials:update', id, data),

    delete: (id: string): Promise<{ success: boolean; message?: string }> =>
      ipcRenderer.invoke('credentials:delete', id),

    search: (query: string): Promise<{ success: boolean; data?: Array<{
      id: string;
      title: string;
      url: string;
      username: string;
      category: string;
    }> }> =>
      ipcRenderer.invoke('credentials:search', query),

    categories: (): Promise<{ success: boolean; data?: string[] }> =>
      ipcRenderer.invoke('credentials:categories'),
  },

  password: {
    generate: (length?: number, options?: {
      includeUppercase?: boolean;
      includeLowercase?: boolean;
      includeNumbers?: boolean;
      includeSymbols?: boolean;
    }): Promise<{ success: boolean; data?: string }> =>
      ipcRenderer.invoke('password:generate', length, options),
  },

  clipboard: {
    copy: (text: string): Promise<{ success: boolean }> =>
      ipcRenderer.invoke('clipboard:copy', text),
  },

  activity: {
    ping: (): Promise<{ success: boolean }> =>
      ipcRenderer.invoke('activity:ping'),
  },
};

contextBridge.exposeInMainWorld('api', api);

export type SecureVaultAPI = typeof api;

