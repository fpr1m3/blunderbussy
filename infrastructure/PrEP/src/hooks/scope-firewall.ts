/**
 * Agent Opulence - Scope Firewall Hook
 *
 * PreToolUse hook that validates targets against engagement scope.
 * Blocks out-of-scope targets and prompts for expansion.
 */

import {
  ScopeManager,
  ScopeValidationResult,
  ToolCallEvent,
  HookDecision,
} from '../lib';

// Global scope manager instance (initialized by session-restore hook)
let scopeManager: ScopeManager | null = null;

/**
 * Set the scope manager instance
 */
export function setScopeManager(manager: ScopeManager): void {
  scopeManager = manager;
}

/**
 * Get the current scope manager
 */
export function getScopeManager(): ScopeManager | null {
  return scopeManager;
}

/**
 * Extract targets from tool input
 */
function extractTargets(input: Record<string, unknown>): string[] {
  const targets: string[] = [];
  const targetFields = [
    'target',
    'targets',
    'host',
    'hosts',
    'ip',
    'domain',
    'url',
    'rhost',
    'rhosts',
    'uri',
  ];

  for (const field of targetFields) {
    const value = input[field];
    if (typeof value === 'string' && value.trim()) {
      // Handle comma-separated or space-separated lists
      const parts = value.split(/[,\s]+/).filter((p) => p.trim());
      targets.push(...parts);
    } else if (Array.isArray(value)) {
      for (const v of value) {
        if (typeof v === 'string' && v.trim()) {
          targets.push(v.trim());
        }
      }
    }
  }

  return [...new Set(targets)]; // Deduplicate
}

/**
 * Build user prompt for scope expansion
 */
function buildExpansionPrompt(
  tool: string,
  outOfScope: ScopeValidationResult[]
): string {
  const lines: string[] = [
    '[SCOPE VIOLATION DETECTED]',
    '',
    `Tool: ${tool}`,
    '',
    'The following targets are OUT OF SCOPE:',
    '',
  ];

  for (const result of outOfScope) {
    lines.push(`  - ${result.target}`);
    lines.push(`    Reason: ${result.reason}`);
  }

  lines.push('');
  lines.push('Options:');
  lines.push('  [E] Request scope expansion for these targets');
  lines.push('  [S] Skip out-of-scope targets and proceed');
  lines.push('  [A] Abort this operation');
  lines.push('');
  lines.push('Choose [E/S/A]:');

  return lines.join('\n');
}

/**
 * Main hook handler
 */
export async function handlePreToolUse(
  event: ToolCallEvent
): Promise<HookDecision> {
  // Skip if no scope manager
  if (!scopeManager) {
    return {
      allow: true,
      reason: 'No scope configured - allowing all targets',
    };
  }

  // Extract targets from input
  const targets = extractTargets(event.input);

  // If no targets, allow
  if (targets.length === 0) {
    return {
      allow: true,
      reason: 'No targets specified',
    };
  }

  // Validate each target
  const validations = scopeManager.validateTargets(targets);
  const outOfScope: ScopeValidationResult[] = [];
  const inScope: string[] = [];

  for (const [target, result] of validations) {
    if (result.inScope) {
      inScope.push(target);
    } else {
      outOfScope.push(result);
    }
  }

  // All in scope - allow
  if (outOfScope.length === 0) {
    return {
      allow: true,
      reason: `All ${targets.length} target(s) are in scope`,
    };
  }

  // Some out of scope - check if any pending expansion
  for (const result of outOfScope) {
    const pending = scopeManager.hasPendingExpansion(result.target);
    if (pending && pending.status === 'approved') {
      // Expansion was approved, remove from out-of-scope
      outOfScope.splice(outOfScope.indexOf(result), 1);
      inScope.push(result.target);
    }
  }

  // Still have out-of-scope targets
  if (outOfScope.length > 0) {
    // Block and prompt user
    return {
      allow: false,
      reason: `${outOfScope.length} target(s) are out of scope`,
      userPrompt: buildExpansionPrompt(event.tool, outOfScope),
    };
  }

  // All targets resolved
  return {
    allow: true,
    reason: 'All targets validated or approved for expansion',
  };
}

/**
 * Handle user response to scope expansion prompt
 */
export function handleExpansionResponse(
  response: string,
  outOfScope: ScopeValidationResult[],
  event: ToolCallEvent
): HookDecision {
  const choice = response.trim().toUpperCase()[0];

  switch (choice) {
    case 'E':
      // Request expansion for all out-of-scope targets
      if (scopeManager) {
        for (const result of outOfScope) {
          const existing = scopeManager.hasPendingExpansion(result.target);
          if (!existing) {
            scopeManager.requestExpansion(
              result.target,
              `Discovered during ${event.tool} operation`,
              event.namespace || 'unknown',
              event.tool,
              []
            );
          }
        }
      }
      return {
        allow: false,
        reason: 'Expansion requested - awaiting approval',
        userPrompt: `Expansion requested for ${outOfScope.length} target(s). Use /opulence-scope approve to allow.`,
      };

    case 'S':
      // Skip out-of-scope targets
      const inScopeOnly = extractTargets(event.input).filter((t) => {
        const result = scopeManager?.validateTarget(t);
        return result?.inScope;
      });

      if (inScopeOnly.length === 0) {
        return {
          allow: false,
          reason: 'No in-scope targets remaining after filtering',
        };
      }

      // Modify input to only include in-scope targets
      const modifiedInput = { ...event.input };
      for (const field of ['target', 'host', 'rhost', 'ip', 'domain']) {
        if (event.input[field]) {
          if (Array.isArray(event.input[field])) {
            modifiedInput[field] = inScopeOnly;
          } else {
            modifiedInput[field] = inScopeOnly.join(',');
          }
        }
      }

      return {
        allow: true,
        modified: true,
        modifiedInput,
        reason: `Proceeding with ${inScopeOnly.length} in-scope target(s)`,
      };

    case 'A':
    default:
      return {
        allow: false,
        reason: 'Operation aborted by user',
      };
  }
}

/**
 * Export for Claude Code hook integration
 */
export default {
  name: 'scope-firewall',
  events: ['mcp:*', 'builtin:Bash'],
  handler: handlePreToolUse,
};
