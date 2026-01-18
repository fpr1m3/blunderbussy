/**
 * Agent Opulence - Policy Enforcer Hook
 *
 * PreToolUse hook that enforces namespace policy (ALLOW/ASK/DENY).
 * Integrates with scope validation for conditional policies.
 */

import {
  PolicyEngine,
  PolicyEvaluationResult,
  ToolCallEvent,
  HookDecision,
  PolicyConfig,
} from '../lib';
import { getScopeManager } from './scope-firewall';
import * as fs from 'fs/promises';
import * as path from 'path';

// Global policy engine instance
let policyEngine: PolicyEngine | null = null;
let policyPath: string = './policy.json';

/**
 * Initialize the policy engine
 */
export async function initializePolicyEngine(configPath?: string): Promise<void> {
  if (configPath) {
    policyPath = configPath;
  }

  try {
    const content = await fs.readFile(policyPath, 'utf-8');
    const config = JSON.parse(content) as PolicyConfig;
    const scopeManager = getScopeManager();
    policyEngine = new PolicyEngine(config, scopeManager || undefined);
  } catch (error) {
    console.error(`Failed to load policy from ${policyPath}:`, error);
    // Use default restrictive policy
    policyEngine = new PolicyEngine(
      {
        version: '1.0.0',
        updated: new Date().toISOString(),
        defaultAction: 'ASK',
        rules: [],
        toolOverrides: {},
      },
      getScopeManager() || undefined
    );
  }
}

/**
 * Get the policy engine instance
 */
export function getPolicyEngine(): PolicyEngine | null {
  return policyEngine;
}

/**
 * Update policy engine with new scope manager
 */
export function updatePolicyScope(): void {
  if (policyEngine) {
    const scopeManager = getScopeManager();
    if (scopeManager) {
      policyEngine.setScopeManager(scopeManager);
    }
  }
}

/**
 * Build user prompt for ASK actions
 */
function buildApprovalPrompt(
  event: ToolCallEvent,
  result: PolicyEvaluationResult
): string {
  const lines: string[] = [
    '[APPROVAL REQUIRED]',
    '',
    `Tool: ${event.namespace ? `${event.namespace}:${event.tool}` : event.tool}`,
  ];

  if (result.matchedRule) {
    lines.push(`Policy: ${result.matchedRule.id}`);
    lines.push(`Reason: ${result.matchedRule.reason || 'Requires approval'}`);
  }

  lines.push('');
  lines.push('Input Parameters:');

  // Show sanitized input (hide potentially sensitive values)
  const sanitizedInput = sanitizeInput(event.input);
  for (const [key, value] of Object.entries(sanitizedInput)) {
    const displayValue = typeof value === 'string'
      ? value.slice(0, 100) + (value.length > 100 ? '...' : '')
      : JSON.stringify(value).slice(0, 100);
    lines.push(`  ${key}: ${displayValue}`);
  }

  lines.push('');
  lines.push('Allow this operation? [y/N]:');

  return lines.join('\n');
}

/**
 * Sanitize input for display (hide potential secrets)
 */
function sanitizeInput(input: Record<string, unknown>): Record<string, unknown> {
  const sensitiveKeys = ['password', 'passwd', 'secret', 'token', 'key', 'credential'];
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(input)) {
    const lowerKey = key.toLowerCase();
    if (sensitiveKeys.some((s) => lowerKey.includes(s))) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Main hook handler
 */
export async function handlePreToolUse(
  event: ToolCallEvent
): Promise<HookDecision> {
  // Initialize policy engine if not done
  if (!policyEngine) {
    await initializePolicyEngine();
  }

  if (!policyEngine) {
    return {
      allow: false,
      reason: 'Policy engine not initialized',
    };
  }

  // Evaluate the tool call against policy
  const result = policyEngine.evaluate(event);

  switch (result.action) {
    case 'ALLOW':
      return {
        allow: true,
        reason: result.matchedRule
          ? `Allowed by policy: ${result.matchedRule.id}`
          : 'Allowed by default policy',
      };

    case 'DENY':
      return {
        allow: false,
        reason: result.denialReason || 'Denied by policy',
      };

    case 'ASK':
      return {
        allow: false,
        reason: 'Requires approval',
        userPrompt: buildApprovalPrompt(event, result),
      };

    default:
      return {
        allow: false,
        reason: 'Unknown policy action',
      };
  }
}

/**
 * Handle user response to approval prompt
 */
export function handleApprovalResponse(
  response: string,
  event: ToolCallEvent
): HookDecision {
  const approved = response.trim().toLowerCase() === 'y' ||
    response.trim().toLowerCase() === 'yes';

  if (approved) {
    return {
      allow: true,
      reason: 'Approved by user',
    };
  }

  return {
    allow: false,
    reason: 'Denied by user',
  };
}

/**
 * Check if a tool is allowed without user interaction
 */
export function isToolAllowed(namespace: string | undefined, tool: string): boolean {
  if (!policyEngine) {
    return false;
  }
  return policyEngine.isAllowed(namespace, tool);
}

/**
 * Get the policy action for a tool
 */
export function getToolPolicy(namespace: string | undefined, tool: string): string {
  if (!policyEngine) {
    return 'ASK';
  }
  return policyEngine.getAction(namespace, tool);
}

/**
 * Export for Claude Code hook integration
 */
export default {
  name: 'policy-enforcer',
  events: ['*'],
  handler: handlePreToolUse,
};
