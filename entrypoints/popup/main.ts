/**
 * GatePaste — Popup Script
 */

import { getAuditLog, get, set } from '../../utils/storage';

function updateStatus() {
  const indicator = document.getElementById('statusIndicator')!;
  const statusText = document.getElementById('statusText')!;
  const domainDisplay = document.getElementById('domainDisplay')!;
  const pauseBtn = document.getElementById('pauseBtn')!;

  get('config').then((config) => {
    const enabled = config.enabled;
    indicator.className = `status-dot ${enabled ? 'active' : 'inactive'}`;
    statusText.textContent = enabled ? 'Active' : 'Paused';
    pauseBtn.textContent = enabled ? '🔇 Pause for Site' : '🔊 Resume for Site';
  });

  // Show current tab domain
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0]?.url;
    if (url) {
      try {
        domainDisplay.textContent = new URL(url).hostname;
      } catch {
        domainDisplay.textContent = 'Unknown';
      }
    }
  });
}

async function updateScanCount() {
  const log = await getAuditLog(1000);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayCount = log.filter((e) => e.timestamp >= today.getTime()).length;
  document.getElementById('scanCount')!.textContent = `${todayCount} secret${todayCount !== 1 ? 's' : ''} detected today`;
}

async function handleScan() {
  const resultDiv = document.getElementById('scanResult')!;
  const resultTitle = document.getElementById('resultTitle')!;
  const resultList = document.getElementById('resultList')!;
  const errorMsg = document.getElementById('errorMsg')!;
  const scanBtn = document.getElementById('scanBtn') as HTMLButtonElement;

  errorMsg.hidden = true;
  resultDiv.hidden = true;
  scanBtn.disabled = true;
  scanBtn.textContent = '⏳ Scanning...';

  try {
    const text = await navigator.clipboard.readText();
    if (!text) {
      resultTitle.textContent = '📋 Clipboard is empty';
      resultDiv.hidden = false;
      return;
    }

    // Dynamically import detector (it's a module)
    const { detectSecrets } = await import('../../utils/detector');
    const result = detectSecrets(text);

    if (result.matched) {
      resultTitle.textContent = `⚠ ${result.findings.length} secret${result.findings.length > 1 ? 's' : ''} detected`;
      resultList.innerHTML = result.findings
        .map((f) => `<li class="finding finding-${f.severity}">${f.patternName} <span class="severity-tag ${f.severity}">${f.severity}</span></li>`)
        .join('');
    } else {
      resultTitle.textContent = '✅ No secrets detected';
      resultList.innerHTML = '';
    }
    resultDiv.hidden = false;
  } catch (err) {
    errorMsg.textContent = `Error: ${err instanceof Error ? err.message : 'Could not read clipboard'}`;
    errorMsg.hidden = false;
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = '📋 Scan Clipboard';
  }
}

// ── Event Listeners ────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  updateStatus();
  updateScanCount();

  document.getElementById('scanBtn')!.addEventListener('click', handleScan);
  document.getElementById('optionsBtn')!.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
  document.getElementById('pauseBtn')!.addEventListener('click', () => {
    get('config').then((config) => {
      config.enabled = !config.enabled;
      set('config', config);
      updateStatus();
    });
  });
});
