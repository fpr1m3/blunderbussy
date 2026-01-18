/**
 * Agent Opulence - Output Processor Hook
 *
 * PostToolUse hook that processes tool output with hybrid masking.
 * Extracts findings and compresses verbose output.
 */

import {
  ContextManager,
  ToolCallEvent,
  KeyFinding,
  MaskedToolOutput,
} from '../lib';

// Global context manager instance
let contextManager: ContextManager | null = null;

/**
 * Set the context manager instance
 */
export function setContextManager(manager: ContextManager): void {
  contextManager = manager;
}

/**
 * Get the context manager
 */
export function getContextManager(): ContextManager | null {
  return contextManager;
}

/**
 * Extract target from tool input
 */
function extractTarget(input: Record<string, unknown>): string | undefined {
  const targetFields = ['target', 'host', 'rhost', 'ip', 'domain', 'url'];
  for (const field of targetFields) {
    const value = input[field];
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
  }
  return undefined;
}

/**
 * Determine if tool output should be processed
 */
function shouldProcessOutput(namespace: string | undefined, tool: string): boolean {
  const processableNamespaces = ['hexstrike', 'metasploit', 'msf', 'sliver'];
  const processableTools = ['nmap', 'nuclei', 'httpx', 'subfinder', 'gobuster', 'ffuf'];

  if (namespace) {
    for (const ns of processableNamespaces) {
      if (namespace.toLowerCase().includes(ns)) {
        return true;
      }
    }
  }

  return processableTools.includes(tool.toLowerCase());
}

/**
 * Format findings for notification
 */
function formatFindingsNotification(findings: KeyFinding[]): string | undefined {
  const critical = findings.filter((f) => f.severity === 'critical');
  const high = findings.filter((f) => f.severity === 'high');

  if (critical.length === 0 && high.length === 0) {
    return undefined;
  }

  const lines: string[] = ['[KEY FINDINGS DETECTED]', ''];

  for (const finding of critical) {
    lines.push(`[!] CRITICAL: ${finding.title}`);
  }

  for (const finding of high) {
    lines.push(`[H] HIGH: ${finding.title}`);
  }

  return lines.join('\n');
}

/**
 * Main hook handler
 */
export async function handlePostToolUse(
  event: ToolCallEvent,
  output: string
): Promise<{
  processedOutput: string;
  findings: KeyFinding[];
  tokensSaved: number;
  notification?: string;
}> {
  // Skip if no context manager or output is small
  if (!contextManager || !output || output.length < 500) {
    return {
      processedOutput: output,
      findings: [],
      tokensSaved: 0,
    };
  }

  // Skip if not a processable tool
  if (!shouldProcessOutput(event.namespace, event.tool)) {
    return {
      processedOutput: output,
      findings: [],
      tokensSaved: 0,
    };
  }

  // Process with hybrid masking
  const target = extractTarget(event.input);
  const result: MaskedToolOutput = contextManager.processToolOutput(
    event.tool,
    output,
    target
  );

  // Build notification for critical/high findings
  const notification = formatFindingsNotification(result.findings);

  return {
    processedOutput: result.masked,
    findings: result.findings,
    tokensSaved: result.tokensSaved,
    notification,
  };
}

/**
 * Get context statistics
 */
export function getContextStats(): {
  tokens: { current: number; max: number; percentage: number };
  findings: number;
  artifacts: number;
} | null {
  if (!contextManager) return null;
  return contextManager.getStats();
}

/**
 * Get current context snapshot for agents
 */
export function getAgentContext(): string {
  if (!contextManager) {
    return 'No context available';
  }
  return contextManager.generateAgentContext();
}

/**
 * Retrieve artifact by ID
 */
export function getArtifact(id: string): string | undefined {
  if (!contextManager) return undefined;
  return contextManager.getArtifact(id);
}

/**
 * Export for Claude Code hook integration
 */
export default {
  name: 'output-processor',
  events: ['mcp:hexstrike:*', 'mcp:metasploit:*', 'mcp:sliver:*'],
  handler: handlePostToolUse,
};
