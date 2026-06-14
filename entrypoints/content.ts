/**
 * GatePaste — Content Script
 *
 * Intercepts paste events, runs the detection engine, and shows
 * the warning overlay if secrets are found.
 *
 * Runs in ISOLATED world — page JS cannot tamper with detection.
 *
 * Note: `defineContentScript` is auto-imported by WXT in entrypoints.
 */

import { detectSecrets } from '../utils/detector';
import { showOverlay } from '../utils/overlay';
import type { OverlayAction } from '../utils/overlay';
import type { Finding } from '../utils/detector';
import { addAuditEntry } from '../utils/storage';

export default defineContentScript({
  matches: ['<all_urls>'],
  main() {
    // ── Paste Interception ──────────────────────────────────────────────────
    document.addEventListener('paste', async (event: ClipboardEvent) => {
      const config = await getConfig();
      if (!config.enabled) return;

      const text = await navigator.clipboard.readText().catch(() => '');
      if (!text || text.length < 8) return;

      // Check domain rules
      const domain = window.location.hostname;
      const matchingRule = config.domainRules.find(
        (r) => domain.includes(r.domain) || r.domain.includes(domain),
      );
      if (matchingRule?.action === 'allow') return;
      if (matchingRule?.action === 'block') {
        event.preventDefault();
        return;
      }

      // Run detection
      const result = detectSecrets(text, {
        minSeverity: (config.minSeverity ?? 'low') as import('../utils/patterns').Severity,
        currentDomain: domain,
      });
      if (!result.matched) return;

      // Intercept the paste
      event.preventDefault();
      const action = await showOverlay(result.findings);
      await handleAction(action, text, result.findings, domain);
    });

    // ── SPA Navigation Handling ─────────────────────────────────────────────
    let lastUrl = location.href;
    new MutationObserver(() => {
      const url = location.href;
      if (url !== lastUrl) {
        lastUrl = url;
      }
    }).observe(document, { subtree: true, childList: true });
  },
});

// ── Helpers ─────────────────────────────────────────────────────────────

async function getConfig(): Promise<{
  enabled: boolean;
  minSeverity: string;
  domainRules: { domain: string; action: string }[];
}> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, (response) => {
      if (response) {
        resolve(response as {
          enabled: boolean;
          minSeverity: string;
          domainRules: { domain: string; action: string }[];
        });
      } else {
        resolve({ enabled: true, minSeverity: 'low', domainRules: [] });
      }
    });
  });
}

async function handleAction(
  action: OverlayAction,
  originalText: string,
  findings: Finding[],
  domain: string,
): Promise<void> {
  for (const finding of findings) {
    await addAuditEntry({
      timestamp: Date.now(),
      domain,
      patternId: finding.patternId,
      patternName: finding.patternName,
      severity: finding.severity,
      action: action === 'mask' ? 'masked' : action === 'raw' ? 'pasted' : 'blocked',
    }).catch(() => {});
  }

  if (action === 'mask') {
    insertText(maskSecrets(originalText, findings));
  } else if (action === 'raw') {
    insertText(originalText);
  }
}

function insertText(text: string): void {
  const active = document.activeElement;

  if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) {
    const start = active.selectionStart ?? active.value.length;
    const end = active.selectionEnd ?? start;
    active.value = active.value.slice(0, start) + text + active.value.slice(end);
    active.selectionStart = active.selectionEnd = start + text.length;
    active.dispatchEvent(new Event('input', { bubbles: true }));
    return;
  }

  if (active instanceof HTMLIFrameElement) {
    try {
      const iframeDoc = active.contentDocument || active.contentWindow?.document;
      if (iframeDoc?.activeElement) {
        const el = iframeDoc.activeElement;
        if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
          const start = el.selectionStart ?? el.value.length;
          const end = el.selectionEnd ?? start;
          el.value = el.value.slice(0, start) + text + el.value.slice(end);
          el.selectionStart = el.selectionEnd = start + text.length;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          return;
        }
      }
    } catch {
      // Cross-origin iframe — fall through
    }
  }

  const selection = window.getSelection();
  if (selection && selection.rangeCount > 0) {
    document.execCommand('insertText', false, text);
    return;
  }

  const clipboardEvent = new ClipboardEvent('paste', {
    clipboardData: new DataTransfer(),
    bubbles: true,
    cancelable: true,
  });
  if (clipboardEvent.clipboardData) {
    clipboardEvent.clipboardData.setData('text/plain', text);
    document.activeElement?.dispatchEvent(clipboardEvent);
  }
}

function maskSecrets(text: string, findings: Finding[]): string {
  const sorted = [...findings].sort((a, b) => b.index - a.index);
  let result = text;
  for (const f of sorted) {
    const masked = f.match.length > 8
      ? f.match.slice(0, 4) + '*'.repeat(Math.min(f.match.length - 8, 40)) + f.match.slice(-4)
      : '*'.repeat(f.match.length);
    result = result.slice(0, f.index) + masked + result.slice(f.index + f.length);
  }
  return result;
}
