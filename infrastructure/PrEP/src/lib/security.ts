/**
 * Agent Opulence - Namespace Policy Engine
 *
 * Evaluates tool calls against policy rules.
 * Implements ALLOW/ASK/DENY permission model.
 *
 * Key Features:
 * - Namespace matching with wildcards
 * - Conditional policy evaluation
 * - Integration with scope validation
 * - Policy caching for performance
 */

import {
  PolicyConfig,
  PolicyRule,
  PolicyAction,
  PolicyCondition,
  PolicyEvaluationResult,
  ToolCallEvent,
  ScopeValidationResult,
} from '../types';
import { ScopeManager } from './scope-manager';

// ============================================================================
// Policy Matching Utilities
// ============================================================================

/**
 * Match a tool name against a pattern (supports wildcards)
 *
 * Examples:
 *   matchTool("exploit/windows/smb/ms17_010", "exploit/*") -> true
 *   matchTool("sessions_list", "sessions_list") -> true
 *   matchTool("generate", "*") -> true
 */
function matchTool(tool: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (pattern === tool) return true;

  // Wildcard suffix match
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -2);
    return tool.startsWith(prefix);
  }

  // Wildcard prefix match
  if (pattern.startsWith('*/')) {
    const suffix = pattern.slice(2);
    return tool.endsWith(suffix);
  }

  return false;
}

/**
 * Build a fully qualified tool identifier
 */
function buildToolId(namespace: string | undefined, tool: string): string {
  if (namespace) {
    return `${namespace}:${tool}`;
  }
  return tool;
}

/**
 * Parse a fully qualified tool identifier
 */
function parseToolId(toolId: string): { namespace: string; tool: string } {
  const parts = toolId.split(':');
  if (parts.length >= 2) {
    // Handle nested namespaces like mcp:metasploit:exploit/windows
    const namespace = parts.slice(0, -1).join(':');
    const tool = parts[parts.length - 1];
    return { namespace, tool };
  }
  return { namespace: 'builtin', tool: toolId };
}

// ============================================================================
// Condition Evaluation
// ============================================================================

/**
 * Evaluate a single condition against tool input
 */
function evaluateCondition(
  condition: PolicyCondition,
  input: Record<string, unknown>,
  scopeManager?: ScopeManager
): boolean {
  const fieldValue = getNestedValue(input, condition.field);

  switch (condition.operator) {
    case 'equals':
      return fieldValue === condition.value;

    case 'contains':
      if (typeof fieldValue === 'string' && typeof condition.value === 'string') {
        return fieldValue.includes(condition.value);
      }
      if (Array.isArray(fieldValue) && typeof condition.value === 'string') {
        return fieldValue.includes(condition.value);
      }
      return false;

    case 'matches':
      if (typeof fieldValue === 'string' && typeof condition.value === 'string') {
        try {
          const regex = new RegExp(condition.value);
          return regex.test(fieldValue);
        } catch {
          return false;
        }
      }
      return false;

    case 'in_scope':
      if (!scopeManager) return true; // No scope manager = skip check
      const targets = extractTargets(input);
      return evaluateScopeCondition(targets, condition.value, scopeManager);

    default:
      return false;
  }
}

/**
 * Get a nested value from an object using dot notation
 */
function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    if (typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

/**
 * Extract target values from tool input
 */
function extractTargets(input: Record<string, unknown>): string[] {
  const targets: string[] = [];

  // Common target field names
  const targetFields = ['target', 'targets', 'host', 'hosts', 'ip', 'domain', 'url', 'rhost', 'rhosts'];

  for (const field of targetFields) {
    const value = input[field];
    if (typeof value === 'string') {
      targets.push(value);
    } else if (Array.isArray(value)) {
      for (const v of value) {
        if (typeof v === 'string') targets.push(v);
      }
    }
  }

  return targets;
}

/**
 * Evaluate scope condition
 */
function evaluateScopeCondition(
  targets: string[],
  scopeRequirement: string | string[],
  scopeManager: ScopeManager
): boolean {
  if (targets.length === 0) return true; // No targets = pass

  const requirement = typeof scopeRequirement === 'string' ? scopeRequirement : scopeRequirement[0];

  switch (requirement) {
    case 'any':
      // At least one target must be in scope
      return targets.some((t) => scopeManager.validateTarget(t).inScope);

    case 'all':
      // All targets must be in scope
      return targets.every((t) => scopeManager.validateTarget(t).inScope);

    case 'none':
      // Used for DENY rules - triggers if target is out of scope
      return targets.some((t) => !scopeManager.validateTarget(t).inScope);

    case 'domain':
      // Target must be a domain in scope
      return targets.some((t) => {
        const result = scopeManager.validateTarget(t);
        return result.inScope && result.matchedRule?.startsWith('Domain:');
      });

    case 'ip':
      // Target must be an IP in scope
      return targets.some((t) => {
        const result = scopeManager.validateTarget(t);
        return result.inScope && result.matchedRule?.startsWith('CIDR:');
      });

    default:
      return true;
  }
}

// ============================================================================
// Policy Engine Class
// ============================================================================

export class PolicyEngine {
  private config: PolicyConfig;
  private scopeManager?: ScopeManager;
  private ruleCache: Map<string, PolicyRule | null>;

  constructor(config: PolicyConfig, scopeManager?: ScopeManager) {
    this.config = config;
    this.scopeManager = scopeManager;
    this.ruleCache = new Map();
  }

  /**
   * Update scope manager (e.g., after scope expansion)
   */
  setScopeManager(scopeManager: ScopeManager): void {
    this.scopeManager = scopeManager;
    // Clear cache when scope changes
    this.ruleCache.clear();
  }

  /**
   * Update policy configuration
   */
  updateConfig(config: PolicyConfig): void {
    this.config = config;
    this.ruleCache.clear();
  }

  /**
   * Evaluate a tool call against policy
   */
  evaluate(event: ToolCallEvent): PolicyEvaluationResult {
    const toolId = buildToolId(event.namespace, event.tool);

    // Check tool overrides first
    const override = this.checkOverrides(toolId);
    if (override) {
      return this.buildResult(override, undefined, event);
    }

    // Find matching rule
    const rule = this.findMatchingRule(event);
    if (rule) {
      return this.buildResult(rule.action, rule, event);
    }

    // Use default action
    return this.buildResult(this.config.defaultAction, undefined, event);
  }

  /**
   * Quick check if a tool is allowed without full evaluation
   */
  isAllowed(namespace: string | undefined, tool: string): boolean {
    const event: ToolCallEvent = {
      tool,
      namespace,
      input: {},
      timestamp: new Date().toISOString(),
      sessionId: 'check',
    };

    const result = this.evaluate(event);
    return result.action === 'ALLOW';
  }

  /**
   * Get the policy action for a tool without full context
   */
  getAction(namespace: string | undefined, tool: string): PolicyAction {
    const toolId = buildToolId(namespace, tool);

    // Check overrides
    const override = this.checkOverrides(toolId);
    if (override) return override;

    // Find rule by namespace and tool pattern
    for (const rule of this.config.rules) {
      if (this.matchesRule(namespace || 'builtin', tool, rule)) {
        // Skip rules with conditions for quick lookup
        if (rule.conditions && rule.conditions.length > 0) continue;
        return rule.action;
      }
    }

    return this.config.defaultAction;
  }

  /**
   * Get all rules for a namespace
   */
  getRulesForNamespace(namespace: string): PolicyRule[] {
    return this.config.rules.filter((rule) => {
      if (rule.namespace === namespace) return true;
      if (rule.namespace.endsWith('*')) {
        const prefix = rule.namespace.slice(0, -1);
        return namespace.startsWith(prefix);
      }
      return false;
    });
  }

  /**
   * Validate tool input against scope
   */
  validateScope(input: Record<string, unknown>): ScopeValidationResult[] {
    if (!this.scopeManager) return [];

    const targets = extractTargets(input);
    return targets.map((t) => this.scopeManager!.validateTarget(t));
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  private checkOverrides(toolId: string): PolicyAction | null {
    // Exact match
    if (this.config.toolOverrides[toolId]) {
      return this.config.toolOverrides[toolId];
    }

    // Wildcard match
    for (const [pattern, action] of Object.entries(this.config.toolOverrides)) {
      if (this.matchToolPattern(toolId, pattern)) {
        return action;
      }
    }

    return null;
  }

  private matchToolPattern(toolId: string, pattern: string): boolean {
    if (pattern === toolId) return true;
    if (pattern === '*') return true;

    // Handle wildcards
    if (pattern.includes('*')) {
      const regex = new RegExp(
        '^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$'
      );
      return regex.test(toolId);
    }

    return false;
  }

  private findMatchingRule(event: ToolCallEvent): PolicyRule | null {
    const namespace = event.namespace || 'builtin';

    for (const rule of this.config.rules) {
      if (!this.matchesRule(namespace, event.tool, rule)) continue;

      // Check conditions
      if (rule.conditions && rule.conditions.length > 0) {
        const conditionsMet = rule.conditions.every((c) =>
          evaluateCondition(c, event.input, this.scopeManager)
        );
        if (!conditionsMet) continue;
      }

      return rule;
    }

    return null;
  }

  private matchesRule(namespace: string, tool: string, rule: PolicyRule): boolean {
    // Match namespace
    if (rule.namespace !== namespace) {
      // Check wildcard namespace
      if (rule.namespace.endsWith(':*')) {
        const prefix = rule.namespace.slice(0, -1);
        if (!namespace.startsWith(prefix)) return false;
      } else if (rule.namespace !== namespace) {
        return false;
      }
    }

    // Match tool
    if (rule.tool) {
      return matchTool(tool, rule.tool);
    }

    return true;
  }

  private buildResult(
    action: PolicyAction,
    rule: PolicyRule | undefined,
    event: ToolCallEvent
  ): PolicyEvaluationResult {
    const result: PolicyEvaluationResult = {
      action,
      matchedRule: rule,
      needsHumanApproval: action === 'ASK',
    };

    if (action === 'ASK') {
      result.approvalPrompt = this.buildApprovalPrompt(event, rule);
    } else if (action === 'DENY') {
      result.denialReason = rule?.reason || 'Denied by policy';
    }

    return result;
  }

  private buildApprovalPrompt(event: ToolCallEvent, rule?: PolicyRule): string {
    const toolId = buildToolId(event.namespace, event.tool);
    const reason = rule?.reason || 'This action requires approval';

    let prompt = `[APPROVAL REQUIRED]\n\nTool: ${toolId}\nReason: ${reason}\n`;

    // Add target info if available
    const targets = extractTargets(event.input);
    if (targets.length > 0) {
      prompt += `\nTargets:\n`;
      for (const target of targets) {
        if (this.scopeManager) {
          const validation = this.scopeManager.validateTarget(target);
          const status = validation.inScope ? 'IN SCOPE' : 'OUT OF SCOPE';
          prompt += `  - ${target} [${status}]\n`;
        } else {
          prompt += `  - ${target}\n`;
        }
      }
    }

    // Add input summary for context
    const inputKeys = Object.keys(event.input).filter(
      (k) => !['target', 'targets', 'host', 'hosts'].includes(k)
    );
    if (inputKeys.length > 0) {
      prompt += `\nParameters:\n`;
      for (const key of inputKeys.slice(0, 5)) {
        const value = event.input[key];
        const display = typeof value === 'string' ? value : JSON.stringify(value);
        prompt += `  ${key}: ${display.slice(0, 100)}${display.length > 100 ? '...' : ''}\n`;
      }
    }

    prompt += `\nAllow this action? [y/N]`;

    return prompt;
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Load policy from JSON file
 */
export async function loadPolicy(path: string): Promise<PolicyConfig> {
  const fs = await import('fs/promises');
  const content = await fs.readFile(path, 'utf-8');
  return JSON.parse(content) as PolicyConfig;
}

/**
 * Create a default restrictive policy
 */
export function createDefaultPolicy(): PolicyConfig {
  return {
    version: '1.0.0',
    updated: new Date().toISOString(),
    defaultAction: 'ASK',
    rules: [
      {
        id: 'read-allow',
        namespace: 'builtin',
        tool: 'Read',
        action: 'ALLOW',
        reason: 'Reading files is safe',
      },
      {
        id: 'glob-allow',
        namespace: 'builtin',
        tool: 'Glob',
        action: 'ALLOW',
        reason: 'Searching files is safe',
      },
      {
        id: 'grep-allow',
        namespace: 'builtin',
        tool: 'Grep',
        action: 'ALLOW',
        reason: 'Searching file contents is safe',
      },
    ],
    toolOverrides: {},
  };
}

/**
 * Create PolicyEngine with scope manager
 */
export function createPolicyEngine(
  config: PolicyConfig,
  scopeManager?: ScopeManager
): PolicyEngine {
  return new PolicyEngine(config, scopeManager);
}
