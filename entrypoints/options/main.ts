/**
 * GatePaste — Options Page Script
 */

import { getAll, set, get, getAuditLog } from '../../utils/storage';
import type { DomainRule } from '../../utils/storage';

async function loadSettings(): Promise<void> {
  const data = await getAll();

  (document.getElementById('enableInterception') as HTMLInputElement).checked = data.config.enabled;
  (document.getElementById('showOverlay') as HTMLInputElement).checked = data.config.showOverlay;
  (document.getElementById('maskByDefault') as HTMLInputElement).checked = data.config.maskByDefault;
  (document.getElementById('sensitivity') as HTMLSelectElement).value = data.config.sensitivity;

  renderDomainRules(data.domainRules);
  renderAuditLog();
}

function renderDomainRules(rules: DomainRule[]): void {
  const container = document.getElementById('domainRules')!;
  container.innerHTML = rules.length === 0
    ? '<p class="placeholder">No domain rules configured.</p>'
    : rules.map((r, i) => `
      <div class="domain-rule" data-index="${i}">
        <span class="domain-name">${r.domain}</span>
        <span class="domain-action action-${r.action}">${r.action}</span>
        <button class="btn-icon remove-rule" data-index="${i}">✕</button>
      </div>
    `).join('');

  // Bind remove handlers
  container.querySelectorAll('.remove-rule').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const idx = parseInt((btn as HTMLElement).dataset.index!);
      const rules = (await get('domainRules')).slice();
      rules.splice(idx, 1);
      await set('domainRules', rules);
      renderDomainRules(rules);
    });
  });
}

async function renderAuditLog(): Promise<void> {
  const container = document.getElementById('auditLog')!;
  const log = await getAuditLog(20);

  container.innerHTML = log.length === 0
    ? '<p class="placeholder">No events yet.</p>'
    : log.map((e) => `
      <div class="audit-entry">
        <span class="audit-domain">${e.domain}</span>
        <span class="audit-pattern">${e.patternName}</span>
        <span class="severity-tag ${e.severity}">${e.severity}</span>
        <span class="audit-action">${e.action}</span>
        <span class="audit-time">${new Date(e.timestamp).toLocaleString()}</span>
      </div>
    `).join('');
}

// ── Event Listeners ────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', loadSettings);

// Auto-save on toggle changes
document.getElementById('enableInterception')?.addEventListener('change', async (e) => {
  const config = (await get('config'));
  config.enabled = (e.target as HTMLInputElement).checked;
  await set('config', config);
});

document.getElementById('showOverlay')?.addEventListener('change', async (e) => {
  const config = (await get('config'));
  config.showOverlay = (e.target as HTMLInputElement).checked;
  await set('config', config);
});

document.getElementById('maskByDefault')?.addEventListener('change', async (e) => {
  const config = (await get('config'));
  config.maskByDefault = (e.target as HTMLInputElement).checked;
  await set('config', config);
});

document.getElementById('sensitivity')?.addEventListener('change', async (e) => {
  const config = (await get('config'));
  config.sensitivity = (e.target as HTMLSelectElement).value as 'low' | 'medium' | 'high';
  await set('config', config);
});

// Add domain rule
document.getElementById('addDomainBtn')?.addEventListener('click', async () => {
  const domainInput = document.getElementById('newDomain') as HTMLInputElement;
  const actionSelect = document.getElementById('newDomainAction') as HTMLSelectElement;
  const domain = domainInput.value.trim().toLowerCase();

  if (!domain) return;

  const rules = (await get('domainRules'));
  if (rules.some((r) => r.domain === domain)) {
    domainInput.value = '';
    return; // already exists
  }

  rules.push({ domain, action: actionSelect.value as DomainRule['action'] });
  await set('domainRules', rules);
  renderDomainRules(rules);
  domainInput.value = '';
});

// Clear audit log
document.getElementById('clearAuditBtn')?.addEventListener('click', async () => {
  if (!window.confirm('Clear all audit log entries? This cannot be undone.')) return;
  await set('auditLog', []);
  renderAuditLog();
});
