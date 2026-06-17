/**
 * GatePaste — Shannon Entropy Calculator
 *
 * Used as a secondary filter: high-entropy strings are more likely to be secrets.
 * Implements classic Shannon entropy: H = -sum(p_i * log2(p_i))
 */

/**
 * Calculate Shannon entropy of a string (bits per byte).
 * Range: 0 (all same char) to 8 (perfectly random).
 */
export function shannonEntropy(str: string): number {
  if (!str) return 0;

  const len = str.length;
  const freq = new Map<string, number>();

  // Count character frequencies
  for (let i = 0; i < len; i++) {
    freq.set(str[i], (freq.get(str[i]) ?? 0) + 1);
  }

  // Calculate entropy
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check if a string has "high entropy" (likely random/secret).
 * Thresholds based on empirical testing:
 *  - Hex strings (e.g. API keys): >3.5 bits/byte
 *  - Base64 strings (e.g. tokens): >4.5 bits/byte
 *  - Mixed-case alphanumeric: >4.0 bits/byte
 */
export function isHighEntropy(str: string, threshold?: number): boolean {
  if (str.length < 10) return false;
  const effectiveThreshold = threshold ?? getEntropyThreshold(str);
  return shannonEntropy(str) >= effectiveThreshold;
}

/**
 * Determine appropriate entropy threshold based on character set.
 */
function getEntropyThreshold(str: string): number {
  if (/[+/=]/.test(str) && str.length > 20) {
    // Likely Base64 — high threshold
    return 4.5;
  }
  if (/^[A-Fa-f0-9]+$/.test(str)) {
    // Hex — medium threshold
    return 3.5;
  }
  if (/[A-Z]/.test(str) && /[a-z]/.test(str) && /\d/.test(str)) {
    // Mixed case + digits
    return 4.0;
  }
  // Default
  return 4.5;
}
