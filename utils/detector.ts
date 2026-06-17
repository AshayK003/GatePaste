/**
 * GatePaste — Detection Engine
 *
 * Runs regex patterns against clipboard text and returns matched secrets.
 * Designed to run in <2ms for 50 patterns.
 */

import type { DetectionPattern, Severity } from './patterns';
import { PATTERNS } from './patterns';
import { isHighEntropy } from './entropy';

export interface DetectionResult {
  matched: boolean;
  findings: Finding[];
  /** Total time to run detection in ms */
  durationMs: number;
}

export interface Finding {
  patternId: string;
  patternName: string;
  severity: Severity;
  /** The full text that matched */
  match: string;
  /** Start index in the original text */
  index: number;
  /** Length of the match */
  length: number;
}

export interface DetectionOptions {
  /** Minimum severity to report (default: 'low' — report everything) */
  minSeverity?: Severity;
  /** Custom patterns to include (optional, from user config) */
  customPatterns?: DetectionPattern[];
  /** Domains to skip detection for */
  allowlistedDomains?: string[];
  /** Current page domain (for allowlist check) */
  currentDomain?: string;
}

const severityOrder: Severity[] = ['low', 'medium', 'high', 'critical'];

/**
 * Run detection on clipboard text.
 * Returns results in <2ms for 50 patterns on typical text (1KB).
 */
export function detectSecrets(text: string, options: DetectionOptions = {}): DetectionResult {
  const start = performance.now();

  // Skip empty or very short text
  if (!text || text.length < 8) {
    return { matched: false, findings: [], durationMs: performance.now() - start };
  }

  const { minSeverity = 'low', customPatterns = [], allowlistedDomains = [], currentDomain = '' } = options;

  // Check domain allowlist
  if (currentDomain && allowlistedDomains.some((d) => currentDomain === d || currentDomain.endsWith('.' + d))) {
    return { matched: false, findings: [], durationMs: performance.now() - start };
  }

  const minIndex = severityOrder.indexOf(minSeverity);
  const allPatterns = [...PATTERNS, ...customPatterns];
  const findings: Finding[] = [];
  const seenMatches = new Set<string>();

  for (const pattern of allPatterns) {
    if (severityOrder.indexOf(pattern.severity) < minIndex) continue;

    // Check context requirement if present
    if (pattern.context && !pattern.context.test(text)) continue;

    const regex = pattern.regex;
    regex.lastIndex = 0;

    // Patterns without the 'g' flag would cause an infinite loop with exec() —
    // test them once instead.
    if (!regex.global) {
      const match = regex.exec(text);
      if (match) {
        const matchedText = match[0].trim();
        if (!seenMatches.has(matchedText)) {
          if (pattern.entropyThreshold !== undefined && !isHighEntropy(matchedText, pattern.entropyThreshold)) continue;
          seenMatches.add(matchedText);
          findings.push({
            patternId: pattern.id,
            patternName: pattern.name,
            severity: pattern.severity,
            match: matchedText,
            index: match.index,
            length: matchedText.length,
          });
        }
      }
      continue;
    }

    // Global patterns: iterate all matches
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      const matchedText = match[0].trim();

      if (seenMatches.has(matchedText)) {
        if (match.index === regex.lastIndex) regex.lastIndex++;
        continue;
      }

      if (pattern.entropyThreshold !== undefined && !isHighEntropy(matchedText, pattern.entropyThreshold)) {
        if (match.index === regex.lastIndex) regex.lastIndex++;
        continue;
      }

      seenMatches.add(matchedText);

      findings.push({
        patternId: pattern.id,
        patternName: pattern.name,
        severity: pattern.severity,
        match: matchedText,
        index: match.index,
        length: matchedText.length,
      });

      if (match.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  findings.sort((a, b) => a.index - b.index);

  return {
    matched: findings.length > 0,
    findings,
    durationMs: performance.now() - start,
  };
}

/**
 * Quick check — returns true if any secrets detected.
 */
export function hasSecrets(text: string, options: DetectionOptions = {}): boolean {
  return detectSecrets(text, options).matched;
}
