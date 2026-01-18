/**
 * Agent Opulence - Key Findings Extractors
 *
 * Extract structured findings from tool output.
 * Reduces verbose tool output to key facts.
 *
 * Key Features:
 * - Pattern-based extraction
 * - Tool-specific parsers
 * - Severity classification
 * - Evidence collection
 */

import { KeyFinding, FindingType } from '../types';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// Extraction Patterns
// ============================================================================

interface ExtractionPattern {
  name: string;
  pattern: RegExp;
  type: FindingType;
  severity: KeyFinding['severity'];
  titleTemplate: string;
  descriptionTemplate: string;
}

const PATTERNS: ExtractionPattern[] = [
  // Credential patterns
  {
    name: 'password_hash',
    pattern: /([a-zA-Z0-9_]+):(\$\d+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+)/g,
    type: 'credential',
    severity: 'high',
    titleTemplate: 'Password hash found: $1',
    descriptionTemplate: 'Found password hash for user $1',
  },
  {
    name: 'plaintext_password',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]+)['"]?/gi,
    type: 'credential',
    severity: 'critical',
    titleTemplate: 'Plaintext password found',
    descriptionTemplate: 'Found plaintext password in output',
  },
  {
    name: 'ssh_key',
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    type: 'credential',
    severity: 'critical',
    titleTemplate: 'SSH private key found',
    descriptionTemplate: 'Found SSH private key in output',
  },
  {
    name: 'api_key',
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
    type: 'credential',
    severity: 'high',
    titleTemplate: 'API key found',
    descriptionTemplate: 'Found potential API key in output',
  },

  // Vulnerability patterns
  {
    name: 'cve_reference',
    pattern: /CVE-(\d{4})-(\d{4,})/gi,
    type: 'vulnerability',
    severity: 'high',
    titleTemplate: 'CVE-$1-$2 referenced',
    descriptionTemplate: 'Vulnerability CVE-$1-$2 identified',
  },
  {
    name: 'sql_injection',
    pattern: /(?:sql\s+injection|sqli|sql\s+error)/gi,
    type: 'vulnerability',
    severity: 'high',
    titleTemplate: 'Potential SQL Injection',
    descriptionTemplate: 'SQL injection indicator found in output',
  },
  {
    name: 'rce_indicator',
    pattern: /(?:remote\s+code\s+execution|rce|command\s+injection)/gi,
    type: 'vulnerability',
    severity: 'critical',
    titleTemplate: 'Potential RCE',
    descriptionTemplate: 'Remote code execution indicator found',
  },

  // Service patterns
  {
    name: 'open_port',
    pattern: /(\d{1,5})\/(?:tcp|udp)\s+open\s+(\S+)/gi,
    type: 'service',
    severity: 'info',
    titleTemplate: 'Open port $1 ($2)',
    descriptionTemplate: 'Service $2 found on port $1',
  },
  {
    name: 'service_version',
    pattern: /(\d{1,5})\/(?:tcp|udp)\s+open\s+(\S+)\s+(.+)/gi,
    type: 'service',
    severity: 'info',
    titleTemplate: 'Service identified: $2',
    descriptionTemplate: 'Port $1: $2 - $3',
  },

  // Subdomain patterns
  {
    name: 'subdomain',
    pattern: /([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/g,
    type: 'subdomain',
    severity: 'info',
    titleTemplate: 'Subdomain: $0',
    descriptionTemplate: 'Discovered subdomain: $0',
  },

  // Pivot patterns
  {
    name: 'internal_network',
    pattern: /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/g,
    type: 'pivot_point',
    severity: 'medium',
    titleTemplate: 'Internal IP: $0',
    descriptionTemplate: 'Internal network address discovered: $0',
  },
];

// ============================================================================
// Tool-Specific Extractors
// ============================================================================

/**
 * Extract findings from nmap output
 */
export function extractFromNmap(output: string, target: string): KeyFinding[] {
  const findings: KeyFinding[] = [];

  // Parse port lines
  const portRegex = /(\d{1,5})\/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.*))?/g;
  let match;

  while ((match = portRegex.exec(output)) !== null) {
    const [, port, protocol, state, service, version] = match;

    if (state === 'open') {
      findings.push({
        id: uuidv4(),
        type: 'service',
        timestamp: new Date().toISOString(),
        source: 'nmap',
        title: `Open port ${port}/${protocol}`,
        description: version
          ? `${service} - ${version}`
          : `${service} service detected`,
        severity: classifyServiceSeverity(service, parseInt(port)),
        evidence: [match[0]],
        artifactRefs: [],
        relatedTargets: [target],
        relatedFindings: [],
      });
    }
  }

  // Check for OS detection
  const osMatch = output.match(/OS details?:\s*(.+)/i);
  if (osMatch) {
    findings.push({
      id: uuidv4(),
      type: 'service',
      timestamp: new Date().toISOString(),
      source: 'nmap',
      title: 'Operating System Identified',
      description: osMatch[1],
      severity: 'info',
      evidence: [osMatch[0]],
      artifactRefs: [],
      relatedTargets: [target],
      relatedFindings: [],
    });
  }

  return findings;
}

/**
 * Extract findings from nuclei output
 */
export function extractFromNuclei(output: string, target: string): KeyFinding[] {
  const findings: KeyFinding[] = [];

  // Parse nuclei output lines
  // Format: [template-id] [severity] [matcher-name] [url] [matched]
  const nucleiRegex = /\[([^\]]+)\]\s*\[(\w+)\]\s*\[([^\]]+)\]\s*(https?:\/\/\S+)(?:\s+(.*))?/g;
  let match;

  while ((match = nucleiRegex.exec(output)) !== null) {
    const [, templateId, severity, matcherName, url, matched] = match;

    findings.push({
      id: uuidv4(),
      type: 'vulnerability',
      timestamp: new Date().toISOString(),
      source: 'nuclei',
      title: templateId.replace(/-/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
      description: matched || `Matched: ${matcherName}`,
      severity: normalizeSeverity(severity),
      evidence: [match[0]],
      artifactRefs: [],
      relatedTargets: [target, url],
      relatedFindings: [],
    });
  }

  return findings;
}

/**
 * Extract findings from httpx output
 */
export function extractFromHttpx(output: string): KeyFinding[] {
  const findings: KeyFinding[] = [];

  // Parse httpx JSON lines
  const lines = output.split('\n').filter((l) => l.trim());

  for (const line of lines) {
    try {
      const data = JSON.parse(line);

      findings.push({
        id: uuidv4(),
        type: 'service',
        timestamp: new Date().toISOString(),
        source: 'httpx',
        title: `Web service: ${data.url || data.host}`,
        description: [
          data.title && `Title: ${data.title}`,
          data.status_code && `Status: ${data.status_code}`,
          data.webserver && `Server: ${data.webserver}`,
          data.tech && `Tech: ${data.tech.join(', ')}`,
        ]
          .filter(Boolean)
          .join(' | '),
        severity: 'info',
        evidence: [line],
        artifactRefs: [],
        relatedTargets: [data.url || data.host],
        relatedFindings: [],
      });
    } catch {
      // Not JSON, try line-based parsing
      const urlMatch = line.match(/(https?:\/\/\S+)/);
      if (urlMatch) {
        findings.push({
          id: uuidv4(),
          type: 'service',
          timestamp: new Date().toISOString(),
          source: 'httpx',
          title: `Web endpoint: ${urlMatch[1]}`,
          description: line,
          severity: 'info',
          evidence: [line],
          artifactRefs: [],
          relatedTargets: [urlMatch[1]],
          relatedFindings: [],
        });
      }
    }
  }

  return findings;
}

/**
 * Extract findings from subfinder output
 */
export function extractFromSubfinder(output: string, baseDomain: string): KeyFinding[] {
  const findings: KeyFinding[] = [];
  const subdomains = output
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && l.includes('.'));

  // Group into single finding with all subdomains
  if (subdomains.length > 0) {
    findings.push({
      id: uuidv4(),
      type: 'subdomain',
      timestamp: new Date().toISOString(),
      source: 'subfinder',
      title: `${subdomains.length} subdomains found for ${baseDomain}`,
      description: `Discovered subdomains: ${subdomains.slice(0, 10).join(', ')}${
        subdomains.length > 10 ? ` and ${subdomains.length - 10} more` : ''
      }`,
      severity: 'info',
      evidence: subdomains.slice(0, 50),
      artifactRefs: [],
      relatedTargets: subdomains,
      relatedFindings: [],
    });
  }

  return findings;
}

/**
 * Extract findings from Metasploit output
 */
export function extractFromMSF(output: string, module: string): KeyFinding[] {
  const findings: KeyFinding[] = [];

  // Session established
  const sessionMatch = output.match(/session\s+(\d+)\s+opened/i);
  if (sessionMatch) {
    findings.push({
      id: uuidv4(),
      type: 'pivot_point',
      timestamp: new Date().toISOString(),
      source: 'metasploit',
      title: `Session ${sessionMatch[1]} established`,
      description: `Metasploit session opened via ${module}`,
      severity: 'critical',
      evidence: [sessionMatch[0]],
      artifactRefs: [],
      relatedTargets: [],
      relatedFindings: [],
    });
  }

  // Credentials found
  const credMatches = output.matchAll(
    /(\S+@\S+|\S+):(\S+)\s*(?:\[([^\]]+)\])?/g
  );
  for (const match of credMatches) {
    const [full, user, pass, context] = match;
    if (pass.length >= 4 && !pass.includes('*')) {
      findings.push({
        id: uuidv4(),
        type: 'credential',
        timestamp: new Date().toISOString(),
        source: 'metasploit',
        title: `Credential found: ${user}`,
        description: context ? `Found in: ${context}` : 'Credential extracted',
        severity: 'high',
        evidence: [full],
        artifactRefs: [],
        relatedTargets: [],
        relatedFindings: [],
      });
    }
  }

  return findings;
}

// ============================================================================
// Generic Extraction
// ============================================================================

/**
 * Extract findings using pattern matching
 */
export function extractFromGeneric(
  output: string,
  source: string,
  target?: string
): KeyFinding[] {
  const findings: KeyFinding[] = [];
  const seen = new Set<string>();

  for (const pattern of PATTERNS) {
    const matches = output.matchAll(pattern.pattern);

    for (const match of matches) {
      // Deduplicate
      const key = `${pattern.name}:${match[0]}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Apply templates
      let title = pattern.titleTemplate;
      let description = pattern.descriptionTemplate;

      for (let i = 0; i < match.length; i++) {
        const placeholder = `$${i}`;
        title = title.replace(placeholder, match[i] || '');
        description = description.replace(placeholder, match[i] || '');
      }

      findings.push({
        id: uuidv4(),
        type: pattern.type,
        timestamp: new Date().toISOString(),
        source,
        title,
        description,
        severity: pattern.severity,
        evidence: [match[0]],
        artifactRefs: [],
        relatedTargets: target ? [target] : [],
        relatedFindings: [],
      });
    }
  }

  return findings;
}

// ============================================================================
// Unified Extractor
// ============================================================================

export interface ExtractionResult {
  findings: KeyFinding[];
  summary: string;
  tokensSaved: number;
}

/**
 * Extract findings from tool output based on tool type
 */
export function extractFindings(
  toolName: string,
  output: string,
  target?: string
): ExtractionResult {
  const normalizedTool = toolName.toLowerCase();
  let findings: KeyFinding[] = [];

  // Route to tool-specific extractor
  if (normalizedTool.includes('nmap')) {
    findings = extractFromNmap(output, target || 'unknown');
  } else if (normalizedTool.includes('nuclei')) {
    findings = extractFromNuclei(output, target || 'unknown');
  } else if (normalizedTool.includes('httpx')) {
    findings = extractFromHttpx(output);
  } else if (normalizedTool.includes('subfinder')) {
    findings = extractFromSubfinder(output, target || 'unknown');
  } else if (normalizedTool.includes('msf') || normalizedTool.includes('metasploit')) {
    findings = extractFromMSF(output, normalizedTool);
  } else {
    // Generic extraction
    findings = extractFromGeneric(output, normalizedTool, target);
  }

  // Calculate token savings
  const originalTokens = estimateTokens(output);
  const findingsTokens = findings.reduce(
    (sum, f) => sum + estimateTokens(JSON.stringify(f)),
    0
  );
  const tokensSaved = Math.max(0, originalTokens - findingsTokens);

  // Generate summary
  const summary = generateFindingsSummary(findings);

  return {
    findings,
    summary,
    tokensSaved,
  };
}

// ============================================================================
// Helper Functions
// ============================================================================

function classifyServiceSeverity(service: string, port: number): KeyFinding['severity'] {
  const highRiskServices = ['telnet', 'ftp', 'rsh', 'rlogin', 'vnc'];
  const mediumRiskServices = ['ssh', 'rdp', 'mysql', 'mssql', 'postgresql'];

  if (highRiskServices.some((s) => service.toLowerCase().includes(s))) {
    return 'medium';
  }
  if (mediumRiskServices.some((s) => service.toLowerCase().includes(s))) {
    return 'low';
  }
  if (port < 1024) {
    return 'info';
  }
  return 'info';
}

function normalizeSeverity(severity: string): KeyFinding['severity'] {
  const normalized = severity.toLowerCase();
  if (['critical', 'crit'].includes(normalized)) return 'critical';
  if (['high', 'hi'].includes(normalized)) return 'high';
  if (['medium', 'med', 'moderate'].includes(normalized)) return 'medium';
  if (['low', 'lo'].includes(normalized)) return 'low';
  return 'info';
}

function estimateTokens(text: string): number {
  // Rough estimation: ~4 characters per token
  return Math.ceil(text.length / 4);
}

function generateFindingsSummary(findings: KeyFinding[]): string {
  if (findings.length === 0) {
    return 'No significant findings extracted.';
  }

  const byType = new Map<FindingType, number>();
  const bySeverity = new Map<KeyFinding['severity'], number>();

  for (const f of findings) {
    byType.set(f.type, (byType.get(f.type) || 0) + 1);
    bySeverity.set(f.severity, (bySeverity.get(f.severity) || 0) + 1);
  }

  const parts: string[] = [`Found ${findings.length} items:`];

  // By severity (most important first)
  for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    const count = bySeverity.get(sev);
    if (count) {
      parts.push(`${count} ${sev}`);
    }
  }

  return parts.join(' ');
}
