/**
 * Generate GatePaste extension icons as SVG files.
 *
 * Creates shield-styled icons at 16, 32, 48, and 128px.
 * Chrome accepts SVGs for unpacked extensions.
 * For CWS submission, convert to PNG via `npx svgexport`.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ICONS_DIR = join(__dirname, '..', 'public', 'icons');

const SIZES = [16, 32, 48, 128];

function generateShieldSvg(size) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 128 128">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#1a1a2e"/>
      <stop offset="100%" stop-color="#16213e"/>
    </linearGradient>
  </defs>
  <!-- Shield shape -->
  <path d="M64 8 L120 32 L120 64 C120 96 96 116 64 124 C32 116 8 96 8 64 L8 32 Z"
        fill="url(#bg)" stroke="#0f3460" stroke-width="2"/>
  <!-- Lock icon -->
  <rect x="44" y="54" width="40" height="30" rx="4" fill="#e94560"/>
  <rect x="52" y="62" width="24" height="14" rx="2" fill="#fff"/>
  <path d="M54 54 L54 48 C54 42 58 38 64 38 C70 38 74 42 74 48 L74 54"
        fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"/>
  <!-- Checkmark -->
  <path d="M72 72 L62 84 L56 76" fill="none" stroke="#4caf50" stroke-width="3"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
}

mkdirSync(ICONS_DIR, { recursive: true });

for (const size of SIZES) {
  const svg = generateShieldSvg(size);
  const filePath = join(ICONS_DIR, `icon-${size}.svg`);
  writeFileSync(filePath, svg, 'utf-8');
  console.log(`Created ${filePath}`);
}

console.log('\nDone! SVG icons created in public/icons/');
console.log('For CWS submission, convert to PNGs:');
console.log('  npm install -g svgexport');
for (const size of SIZES) {
  console.log(`  svgexport public/icons/icon-${size}.svg public/icons/icon-${size}.png ${size}:${size}`);
}
