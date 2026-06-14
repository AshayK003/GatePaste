/**
 * GatePaste — Shadow DOM Warning Overlay
 *
 * Renders a shadow-DOM-isolated warning when secrets are detected in paste.
 * The overlay's shadow root prevents page CSS from tampering with the UI.
 */

import type { Finding } from './detector';

export type OverlayAction = 'mask' | 'raw' | 'cancel';

export interface OverlayConfig {
  /** Text shown at top of overlay */
  title?: string;
  /** Primary action label */
  maskLabel?: string;
  /** Secondary action label */
  rawLabel?: string;
  /** Dismiss label */
  cancelLabel?: string;
  /** Whether to show "Don't ask again for this domain" checkbox */
  showDomainOptOut?: boolean;
}

const STYLES = `
:host {
  all: initial;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 2147483647;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 14px;
  line-height: 1.4;
  color: #1a1a2e;
}
.backdrop {
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background: rgba(0, 0, 0, 0.4);
  backdrop-filter: blur(2px);
}
.card {
  position: relative;
  background: #ffffff;
  border-radius: 12px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
  width: 480px;
  max-width: 90%;
  max-height: 80vh;
  overflow-y: auto;
  padding: 24px;
}
.header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 16px;
}
.header-icon {
  font-size: 24px;
}
.header-title {
  font-size: 18px;
  font-weight: 700;
  color: #d32f2f;
}
.body {
  margin-bottom: 20px;
}
.secret-type {
  font-weight: 600;
  color: #d32f2f;
}
.risk-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
}
.risk-critical {
  background: #d32f2f;
  color: #ffffff;
}
.risk-high {
  background: #f57c00;
  color: #ffffff;
}
.risk-medium {
  background: #fbc02d;
  color: #1a1a2e;
}
.risk-low {
  background: #e0e0e0;
  color: #1a1a2e;
}
.match-value {
  background: #f5f5f5;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 8px 12px;
  margin: 8px 0;
  word-break: break-all;
  font-family: 'SF Mono', 'Menlo', 'Monaco', monospace;
  font-size: 12px;
  color: #333;
}
.warning-text {
  color: #666;
  font-size: 13px;
  margin: 8px 0;
}
.actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.btn {
  padding: 10px 16px;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.15s;
  flex: 1;
  min-width: 100px;
}
.btn:hover { opacity: 0.85; }
.btn:active { opacity: 0.7; }
.btn-mask {
  background: #d32f2f;
  color: #fff;
}
.btn-raw {
  background: #1565c0;
  color: #fff;
}
.btn-cancel {
  background: #e0e0e0;
  color: #333;
}
.opt-out {
  margin-top: 16px;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #888;
  cursor: pointer;
}
`;

/**
 * Show the warning overlay and return the user's decision.
 * Returns a Promise that resolves with the chosen action.
 */
export function showOverlay(
  findings: Finding[],
  config: OverlayConfig = {},
): Promise<OverlayAction> {
  return new Promise((resolve) => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'closed' });

    const topFinding = findings[0];

    // Build severity label
    const severityLabel = topFinding.severity.charAt(0).toUpperCase() + topFinding.severity.slice(1);
    const riskClass = `risk-${topFinding.severity}`;

    // Mask the match for display
    const maskedMatch = topFinding.match.length > 8
      ? topFinding.match.slice(0, 4) + '*'.repeat(Math.min(topFinding.match.length - 8, 40)) + topFinding.match.slice(-4)
      : '*'.repeat(topFinding.match.length);

    shadow.innerHTML = `
      <style>${STYLES}</style>
      <div class="backdrop"></div>
      <div class="card">
        <div class="header">
          <span class="header-icon">🔒</span>
          <span class="header-title">GatePaste</span>
        </div>
        <div class="body">
          <p style="margin: 0 0 4px 0;">
            <span class="secret-type">⚠ Secret Detected</span>
            <span class="risk-badge ${riskClass}">${severityLabel}</span>
          </p>
          <p style="margin: 0 0 8px 0; color: #666; font-size: 13px;">${topFinding.patternName}</p>
          <div class="match-value">${maskedMatch}</div>
          ${findings.length > 1 ? `<p style="color: #888; font-size: 12px; margin: 0;">+${findings.length - 1} more match${findings.length > 2 ? 'es' : ''}</p>` : ''}
          <p class="warning-text">This is a form field. Are you sure you want to paste a credential here?</p>
        </div>
        <div class="actions">
          <button class="btn btn-mask" data-action="mask">${config.maskLabel || 'Mask & Paste'}</button>
          <button class="btn btn-raw" data-action="raw">${config.rawLabel || 'Paste Raw'}</button>
          <button class="btn btn-cancel" data-action="cancel">${config.cancelLabel || 'Cancel'}</button>
        </div>
        ${config.showDomainOptOut !== false ? '<label class="opt-out"><input type="checkbox" id="dontAskAgain"> Don\'t ask again for this domain</label>' : ''}
      </div>
    `;

    // Handle actions
    const handleAction = (action: OverlayAction) => {
      const dontAskAgain = shadow.querySelector('#dontAskAgain') as HTMLInputElement | null;
      const payload = {
        action,
        domainOptOut: dontAskAgain?.checked ?? false,
      };
      host.remove();
      resolve(payload.action);
    };

    shadow.querySelector('[data-action="mask"]')?.addEventListener('click', () => handleAction('mask'));
    shadow.querySelector('[data-action="raw"]')?.addEventListener('click', () => handleAction('raw'));
    shadow.querySelector('[data-action="cancel"]')?.addEventListener('click', () => handleAction('cancel'));

    // Close on backdrop click = cancel
    shadow.querySelector('.backdrop')?.addEventListener('click', () => handleAction('cancel'));

    document.documentElement.appendChild(host);
  });
}
