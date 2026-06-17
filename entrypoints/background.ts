/**
 * GatePaste — Background Service Worker
 *
 * Orchestrates the extension: manages pattern updates, domain rules,
 * audit logging, and forwards messages between content scripts and storage.
 *
 * In MV3, the service worker can terminate after ~30s idle.
 * All persistent state lives in chrome.storage, not global variables.
 *
 * Note: `defineBackground` is auto-imported by WXT in entrypoints.
 */

import { addAuditEntry } from '../utils/storage';
import type { AuditEntry } from '../utils/storage';

function isValidAuditEntry(entry: unknown): entry is AuditEntry {
  return (
    typeof entry === 'object' &&
    entry !== null &&
    typeof (entry as AuditEntry).timestamp === 'number' &&
    typeof (entry as AuditEntry).domain === 'string' &&
    typeof (entry as AuditEntry).patternId === 'string' &&
    typeof (entry as AuditEntry).patternName === 'string' &&
    ['masked', 'pasted', 'blocked'].includes((entry as AuditEntry).action)
  );
}

// ── Message Types ──────────────────────────────────────────────────────

interface AuditLogMessage {
  type: 'AUDIT_LOG';
  entry: AuditEntry;
}

interface ConfigRequestMessage {
  type: 'GET_CONFIG';
}

type ExtensionMessage = AuditLogMessage | ConfigRequestMessage;

export default defineBackground(() => {
  // ── Message Handler ─────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((
    message: ExtensionMessage,
    _sender: chrome.runtime.MessageSender,
    sendResponse: (response?: unknown) => void,
  ): boolean | undefined => {
    switch (message.type) {
      case 'AUDIT_LOG':
        if (!isValidAuditEntry(message.entry)) {
          console.warn('GatePaste: invalid audit entry rejected', message.entry);
          sendResponse({ success: false, error: 'invalid entry' });
          return false;
        }
        addAuditEntry(message.entry).catch(console.error);
        sendResponse({ success: true });
        return true;

      case 'GET_CONFIG':
        chrome.storage.sync.get(['config', 'domainRules'], (data) => {
          sendResponse({
            enabled: data.config?.enabled ?? true,
            minSeverity: data.config?.minSeverity ?? 'low',
            domainRules: data.domainRules ?? [],
          });
        });
        return true;

      default:
        sendResponse({ error: 'Unknown message type' });
        return false;
    }
  });

  // ── Extension Lifecycle ─────────────────────────────────────────────────
  chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.sync.set({
      config: {
        enabled: true,
        showOverlay: true,
        maskByDefault: true,
        sensitivity: 'medium',
        minSeverity: 'low',
      },
      domainRules: [],
      auditLog: [],
    });
  });
});
