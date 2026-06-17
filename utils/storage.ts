/**
 * GatePaste — chrome.storage wrapper
 *
 * Typesafe wrappers around chrome.storage.local and chrome.storage.sync.
 * All extension state goes through here — never use raw chrome.storage calls.
 */

import type { Severity } from './patterns';

export interface GatePasteConfig {
  /** Whether automatic paste interception is enabled */
  enabled: boolean;
  /** Whether to show the warning overlay on detection */
  showOverlay: boolean;
  /** Whether to mask secrets by default */
  maskByDefault: boolean;
  /** Detection sensitivity */
  sensitivity: 'low' | 'medium' | 'high';
  /** Minimum severity to report */
  minSeverity: Severity;
}

export interface DomainRule {
  domain: string;
  action: 'allow' | 'block' | 'ask';
}

export interface AuditEntry {
  timestamp: number;
  domain: string;
  patternId: string;
  patternName: string;
  severity: Severity;
  action: 'masked' | 'pasted' | 'blocked';
}

export interface StorageSchema {
  config: GatePasteConfig;
  domainRules: DomainRule[];
  auditLog: AuditEntry[];
}

const DEFAULTS: StorageSchema = {
  config: {
    enabled: true,
    showOverlay: true,
    maskByDefault: true,
    sensitivity: 'medium',
    minSeverity: 'low',
  },
  domainRules: [],
  auditLog: [],
};

// Audit log goes to local storage to avoid hitting chrome.storage.sync's
// 102,400-byte total quota. Everything else stays in sync for roaming.
const STORAGE: Record<keyof StorageSchema, chrome.storage.StorageArea> = {
  config: chrome.storage.sync,
  domainRules: chrome.storage.sync,
  auditLog: chrome.storage.local,
};

/**
 * Get a value from storage with fallback to defaults.
 */
export async function get<K extends keyof StorageSchema>(key: K): Promise<StorageSchema[K]> {
  const result = await STORAGE[key].get(key);
  return result[key] ?? DEFAULTS[key];
}

/**
 * Set a value in storage.
 */
export async function set<K extends keyof StorageSchema>(key: K, value: StorageSchema[K]): Promise<void> {
  await STORAGE[key].set({ [key]: value });
}

/**
 * Get all config values.
 */
export async function getAll(): Promise<StorageSchema> {
  const result = await chrome.storage.sync.get(null);
  return { ...DEFAULTS, ...result };
}

/**
 * Reset all settings to defaults.
 */
export async function resetAll(): Promise<void> {
  await chrome.storage.sync.clear();
}

/**
 * Add an entry to the audit log.
 * Keeps last 1000 entries to stay under storage quota.
 */
export async function addAuditEntry(entry: AuditEntry): Promise<void> {
  const log = await get('auditLog');
  log.push(entry);
  // Trim to last 1000
  if (log.length > 1000) {
    log.splice(0, log.length - 1000);
  }
  await set('auditLog', log);
}

/**
 * Get the audit log, most recent first.
 */
export async function getAuditLog(limit = 50): Promise<AuditEntry[]> {
  const log = await get('auditLog');
  return log.slice(-limit).reverse();
}
