/**
 * Agent Opulence - Scope Firewall
 *
 * Validates targets against engagement scope.
 * Blocks out-of-scope targets and prompts for expansion.
 *
 * Key Features:
 * - CIDR range validation
 * - Domain pattern matching (with wildcards)
 * - Automatic expansion request generation
 * - Caching for performance
 */

import {
  EngagementScope,
  CIDRRange,
  DomainPattern,
  ScopeValidationResult,
  ScopeExpansionRequest,
  Result,
} from '../types';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// CIDR Utilities
// ============================================================================

/**
 * Parse an IPv4 address into a 32-bit integer
 */
function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

/**
 * Convert 32-bit integer back to IPv4 string
 */
function intToIp(num: number): string {
  return [
    (num >>> 24) & 0xff,
    (num >>> 16) & 0xff,
    (num >>> 8) & 0xff,
    num & 0xff,
  ].join('.');
}

/**
 * Parse CIDR notation into network and mask
 */
function parseCIDR(cidr: string): { network: number; mask: number } {
  const [ip, prefix] = cidr.split('/');
  const prefixLen = parseInt(prefix, 10);

  if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) {
    throw new Error(`Invalid CIDR prefix: ${cidr}`);
  }

  const network = ipToInt(ip);
  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;

  return { network: network & mask, mask };
}

/**
 * Check if an IP address is within a CIDR range
 */
export function isIPInCIDR(ip: string, cidr: string): boolean {
  try {
    const ipInt = ipToInt(ip);
    const { network, mask } = parseCIDR(cidr);
    return (ipInt & mask) === network;
  } catch {
    return false;
  }
}

/**
 * Check if IP is a valid IPv4 address
 */
export function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const num = parseInt(p, 10);
    return !isNaN(num) && num >= 0 && num <= 255 && p === String(num);
  });
}

// ============================================================================
// Domain Matching
// ============================================================================

/**
 * Match domain against pattern (supports wildcards)
 *
 * Examples:
 *   matchDomain("app.target.htb", "*.htb") -> true
 *   matchDomain("target.htb", "*.htb") -> true
 *   matchDomain("app.target.htb", "target.htb") -> false
 *   matchDomain("app.target.htb", "*.target.htb") -> true
 */
export function matchDomain(domain: string, pattern: string): boolean {
  // Normalize
  domain = domain.toLowerCase().trim();
  pattern = pattern.toLowerCase().trim();

  // Exact match
  if (domain === pattern) return true;

  // Wildcard match
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // Keep the dot: ".htb"
    return domain.endsWith(suffix) || domain === pattern.slice(2);
  }

  return false;
}

/**
 * Extract potential domain from various input formats
 */
export function extractDomain(input: string): string | null {
  // Remove protocol
  let domain = input.replace(/^https?:\/\//, '');

  // Remove port
  domain = domain.split(':')[0];

  // Remove path
  domain = domain.split('/')[0];

  // Validate it looks like a domain
  if (domain.includes('.') && !isValidIPv4(domain)) {
    return domain.toLowerCase();
  }

  return null;
}

// ============================================================================
// Scope Manager Class
// ============================================================================

export class ScopeManager {
  private scope: EngagementScope;
  private validationCache: Map<string, ScopeValidationResult>;
  private cacheMaxAge: number = 60000; // 1 minute cache
  private cacheTimestamps: Map<string, number>;

  constructor(scope: EngagementScope) {
    this.scope = scope;
    this.validationCache = new Map();
    this.cacheTimestamps = new Map();
  }

  /**
   * Update the scope (e.g., after expansion approval)
   */
  updateScope(scope: EngagementScope): void {
    this.scope = scope;
    // Clear cache on scope change
    this.validationCache.clear();
    this.cacheTimestamps.clear();
  }

  /**
   * Get current scope
   */
  getScope(): EngagementScope {
    return this.scope;
  }

  /**
   * Validate a target against the current scope
   *
   * Returns validation result with expansion request if needed
   */
  validateTarget(target: string): ScopeValidationResult {
    // Check cache
    const cached = this.getCached(target);
    if (cached) return cached;

    // Perform validation
    const result = this.performValidation(target);

    // Cache result
    this.setCache(target, result);

    return result;
  }

  /**
   * Validate multiple targets efficiently
   */
  validateTargets(targets: string[]): Map<string, ScopeValidationResult> {
    const results = new Map<string, ScopeValidationResult>();

    for (const target of targets) {
      results.set(target, this.validateTarget(target));
    }

    return results;
  }

  /**
   * Request scope expansion for a target
   *
   * Creates an expansion request that must be approved by human
   */
  requestExpansion(
    target: string,
    reason: string,
    requestedBy: string,
    discoveredVia: string,
    relatedFindings: string[] = []
  ): ScopeExpansionRequest {
    const type = this.inferTargetType(target);

    const request: ScopeExpansionRequest = {
      id: uuidv4(),
      requestedAt: new Date().toISOString(),
      requestedBy,
      reason,
      type,
      value: target,
      discoveredVia,
      relatedFindings,
      status: 'pending',
    };

    // Add to pending expansions
    this.scope.pendingExpansions.push(request);

    return request;
  }

  /**
   * Approve a pending expansion request
   */
  approveExpansion(
    requestId: string,
    decidedBy: string = 'human',
    notes?: string
  ): Result<void, Error> {
    const requestIndex = this.scope.pendingExpansions.findIndex(
      (r) => r.id === requestId
    );

    if (requestIndex === -1) {
      return { ok: false, error: new Error(`Request not found: ${requestId}`) };
    }

    const request = this.scope.pendingExpansions[requestIndex];
    request.status = 'approved';

    // Add to scope based on type
    switch (request.type) {
      case 'cidr':
        this.scope.cidrs.push({
          network: request.value,
          description: `Approved expansion: ${request.reason}`,
        });
        break;

      case 'domain':
        this.scope.domains.push({
          pattern: request.value,
          description: `Approved expansion: ${request.reason}`,
        });
        break;

      case 'ip':
        // Add as /32 CIDR
        this.scope.cidrs.push({
          network: `${request.value}/32`,
          description: `Approved expansion: ${request.reason}`,
        });
        break;
    }

    // Move to history
    this.scope.expansionHistory.push({
      request,
      decidedAt: new Date().toISOString(),
      decidedBy,
      decision: 'approved',
      notes,
    });

    // Remove from pending
    this.scope.pendingExpansions.splice(requestIndex, 1);

    // Clear cache
    this.validationCache.clear();
    this.cacheTimestamps.clear();

    return { ok: true, value: undefined };
  }

  /**
   * Deny a pending expansion request
   */
  denyExpansion(
    requestId: string,
    decidedBy: string = 'human',
    notes?: string
  ): Result<void, Error> {
    const requestIndex = this.scope.pendingExpansions.findIndex(
      (r) => r.id === requestId
    );

    if (requestIndex === -1) {
      return { ok: false, error: new Error(`Request not found: ${requestId}`) };
    }

    const request = this.scope.pendingExpansions[requestIndex];
    request.status = 'denied';

    // Move to history
    this.scope.expansionHistory.push({
      request,
      decidedAt: new Date().toISOString(),
      decidedBy,
      decision: 'denied',
      notes,
    });

    // Remove from pending
    this.scope.pendingExpansions.splice(requestIndex, 1);

    return { ok: true, value: undefined };
  }

  /**
   * Get all pending expansion requests
   */
  getPendingExpansions(): ScopeExpansionRequest[] {
    return this.scope.pendingExpansions;
  }

  /**
   * Check if there's already a pending expansion for this target
   */
  hasPendingExpansion(target: string): ScopeExpansionRequest | undefined {
    return this.scope.pendingExpansions.find((r) => r.value === target);
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  private performValidation(target: string): ScopeValidationResult {
    // Check exclusions first
    if (this.isExcluded(target)) {
      return {
        inScope: false,
        target,
        matchedRule: 'exclusion',
        requiresExpansion: false,
        reason: 'Target is explicitly excluded from scope',
      };
    }

    // Check if IP
    if (isValidIPv4(target)) {
      return this.validateIP(target);
    }

    // Check if domain
    const domain = extractDomain(target);
    if (domain) {
      return this.validateDomain(domain, target);
    }

    // Unknown target type - check as potential IP or domain in URL
    return {
      inScope: false,
      target,
      requiresExpansion: true,
      reason: 'Unable to determine target type for scope validation',
    };
  }

  private validateIP(ip: string): ScopeValidationResult {
    // Check each CIDR range
    for (const cidr of this.scope.cidrs) {
      if (isIPInCIDR(ip, cidr.network)) {
        return {
          inScope: true,
          target: ip,
          matchedRule: `CIDR: ${cidr.network}`,
          requiresExpansion: false,
          reason: cidr.description || `IP ${ip} is within ${cidr.network}`,
        };
      }
    }

    // Not in any range
    return {
      inScope: false,
      target: ip,
      requiresExpansion: true,
      reason: `IP ${ip} is not in any authorized CIDR range`,
    };
  }

  private validateDomain(domain: string, originalTarget: string): ScopeValidationResult {
    // Check each domain pattern
    for (const pattern of this.scope.domains) {
      if (matchDomain(domain, pattern.pattern)) {
        return {
          inScope: true,
          target: originalTarget,
          matchedRule: `Domain: ${pattern.pattern}`,
          requiresExpansion: false,
          reason: pattern.description || `Domain ${domain} matches ${pattern.pattern}`,
        };
      }
    }

    // Not matching any pattern
    return {
      inScope: false,
      target: originalTarget,
      requiresExpansion: true,
      reason: `Domain ${domain} does not match any authorized pattern`,
    };
  }

  private isExcluded(target: string): boolean {
    // Check IP exclusions
    if (isValidIPv4(target)) {
      if (this.scope.excludedIPs.includes(target)) {
        return true;
      }
    }

    // Check domain exclusions
    const domain = extractDomain(target);
    if (domain) {
      for (const excluded of this.scope.excludedDomains) {
        if (matchDomain(domain, excluded)) {
          return true;
        }
      }
    }

    return false;
  }

  private inferTargetType(target: string): 'cidr' | 'domain' | 'ip' {
    if (target.includes('/')) return 'cidr';
    if (isValidIPv4(target)) return 'ip';
    return 'domain';
  }

  private getCached(target: string): ScopeValidationResult | null {
    const timestamp = this.cacheTimestamps.get(target);
    if (!timestamp || Date.now() - timestamp > this.cacheMaxAge) {
      this.validationCache.delete(target);
      this.cacheTimestamps.delete(target);
      return null;
    }
    return this.validationCache.get(target) || null;
  }

  private setCache(target: string, result: ScopeValidationResult): void {
    this.validationCache.set(target, result);
    this.cacheTimestamps.set(target, Date.now());
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a default empty scope
 */
export function createEmptyScope(name: string): EngagementScope {
  return {
    id: uuidv4(),
    name,
    created: new Date().toISOString(),
    updated: new Date().toISOString(),
    cidrs: [],
    domains: [],
    excludedIPs: [],
    excludedDomains: [],
    pendingExpansions: [],
    expansionHistory: [],
  };
}

/**
 * Create a scope for HTB machine engagement
 */
export function createHTBScope(
  machineName: string,
  machineIP: string,
  htbDomain?: string
): EngagementScope {
  const scope = createEmptyScope(`HTB: ${machineName}`);

  // Add machine IP as /32
  scope.cidrs.push({
    network: `${machineIP}/32`,
    description: `HTB Machine: ${machineName}`,
  });

  // Add HTB VPN range (common ranges)
  scope.cidrs.push({
    network: '10.129.0.0/16',
    description: 'HTB VPN Range (Starting Point)',
  });

  scope.cidrs.push({
    network: '10.10.10.0/24',
    description: 'HTB VPN Range (Main)',
  });

  // Add domain if provided
  if (htbDomain) {
    scope.domains.push({
      pattern: htbDomain,
      description: `HTB Machine Domain: ${htbDomain}`,
    });

    // Also add wildcard for subdomains
    scope.domains.push({
      pattern: `*.${htbDomain}`,
      description: `HTB Machine Subdomains: *.${htbDomain}`,
    });
  }

  // Always add .htb TLD
  scope.domains.push({
    pattern: '*.htb',
    description: 'HTB TLD wildcard',
  });

  return scope;
}

/**
 * Create a ScopeManager instance with HTB defaults
 */
export function createHTBScopeManager(
  machineName: string,
  machineIP: string,
  htbDomain?: string
): ScopeManager {
  const scope = createHTBScope(machineName, machineIP, htbDomain);
  return new ScopeManager(scope);
}
