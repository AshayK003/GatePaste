import { defineConfig } from 'wxt';

// See https://wxt.dev/api/config.html
export default defineConfig({
  extensionApi: 'chrome',
  manifest: {
    name: 'GatePaste',
    version: '1.0.0',
    description: 'Detect secrets in your clipboard before you paste into web forms',
    permissions: ['clipboardRead', 'storage', 'activeTab'],
    icons: {
      16: '/icons/icon-16.svg',
      32: '/icons/icon-32.svg',
      48: '/icons/icon-48.svg',
      128: '/icons/icon-128.svg',
    },
    action: {
      default_title: 'GatePaste',
      default_popup: 'popup.html',
      default_icon: {
        16: '/icons/icon-16.svg',
        32: '/icons/icon-32.svg',
        48: '/icons/icon-48.svg',
        128: '/icons/icon-128.svg',
      },
    },
  },
  // Auto-import shared utils from the utils/ directory
  imports: {
    dirs: ['utils/**'],
  },
});
