/**
 * Agent Opulence - Context Manager
 *
 * Unified context management with hybrid masking.
 * Reduces token usage while preserving key information.
 *
 * Key Features:
 * - Hybrid masking (summary + artifact reference)
 * - Automatic finding extraction
 * - Rolling window management
 * - Context reconstruction for agents
 */

import {
  ContextWindow,
  ContextSegment,
  ContextSegmentType,
  KeyFinding,
  ToolCallEvent,
  EngagementScope,
} from '../types';
import { WindowManager, createWindowManager, WindowConfig } from './window-manager';
import { extractFindings, ExtractionResult } from './extractors';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// Masking Configuration
// ============================================================================

export interface MaskingConfig {
  // Thresholds for when to mask
  minOutputLengthToMask: number;      // Don't mask outputs smaller than this
  maxUnmaskedToolOutput: number;      // Max tokens for unmasked tool output

  // Summary settings
  maxSummaryLength: number;           // Max characters for summary
  includeEvidenceInSummary: boolean;  // Include evidence snippets

  // Artifact reference settings
  createArtifactRef: boolean;         // Create artifact reference for full output
  artifactRefFormat: 'path' | 'id';   // How to reference artifacts
}

const DEFAULT_MASKING_CONFIG: MaskingConfig = {
  minOutputLengthToMask: 1000,
  maxUnmaskedToolOutput: 2000,
  maxSummaryLength: 500,
  includeEvidenceInSummary: true,
  createArtifactRef: true,
  artifactRefFormat: 'id',
};

// ============================================================================
// Masked Content Types
// ============================================================================

export interface MaskedToolOutput {
  original: string;
  masked: string;
  findings: KeyFinding[];
  artifactId?: string;
  tokensSaved: number;
  compressionRatio: number;
}

export interface ContextSnapshot {
  scope: string;
  findings: string;
  sessions: string;
  recentActivity: string;
  totalTokens: number;
}

// ============================================================================
// Context Manager Class
// ============================================================================

export class ContextManager {
  private windowManager: WindowManager;
  private maskingConfig: MaskingConfig;
  private artifactStore: Map<string, string>;  // In-memory artifact store
  private findingsCache: KeyFinding[];

  constructor(
    windowConfig?: Partial<WindowConfig>,
    maskingConfig?: Partial<MaskingConfig>
  ) {
    this.windowManager = createWindowManager(windowConfig);
    this.maskingConfig = { ...DEFAULT_MASKING_CONFIG, ...maskingConfig };
    this.artifactStore = new Map();
    this.findingsCache = [];
  }

  /**
   * Get the underlying window manager
   */
  getWindowManager(): WindowManager {
    return this.windowManager;
  }

  /**
   * Get all cached findings
   */
  getFindings(): KeyFinding[] {
    return this.findingsCache;
  }

  // ==========================================================================
  // Hybrid Masking
  // ==========================================================================

  /**
   * Process tool output with hybrid masking
   *
   * 1. Extract key findings
   * 2. Generate summary
   * 3. Store full output as artifact reference
   * 4. Return masked version for context
   */
  processToolOutput(
    toolName: string,
    output: string,
    target?: string
  ): MaskedToolOutput {
    const originalTokens = this.estimateTokens(output);

    // Check if masking is needed
    if (output.length < this.maskingConfig.minOutputLengthToMask) {
      return {
        original: output,
        masked: output,
        findings: [],
        tokensSaved: 0,
        compressionRatio: 1.0,
      };
    }

    // Extract findings
    const extraction = extractFindings(toolName, output, target);

    // Store original as artifact
    let artifactId: string | undefined;
    if (this.maskingConfig.createArtifactRef) {
      artifactId = this.storeArtifact(output, toolName);
    }

    // Generate masked content
    const masked = this.generateMaskedContent(
      toolName,
      extraction,
      artifactId,
      target
    );

    // Add findings to cache
    this.findingsCache.push(...extraction.findings);

    // Add to window
    this.windowManager.addMaskedSegment(
      'tool_output',
      masked,
      originalTokens,
      3 // Low priority for tool output
    );

    // Add high-priority findings as separate segments
    for (const finding of extraction.findings) {
      if (finding.severity === 'critical' || finding.severity === 'high') {
        this.windowManager.addSegment(
          'finding',
          this.formatFinding(finding),
          7
        );
      }
    }

    const maskedTokens = this.estimateTokens(masked);

    return {
      original: output,
      masked,
      findings: extraction.findings,
      artifactId,
      tokensSaved: Math.max(0, originalTokens - maskedTokens),
      compressionRatio: maskedTokens / originalTokens,
    };
  }

  /**
   * Generate masked content from extraction result
   */
  private generateMaskedContent(
    toolName: string,
    extraction: ExtractionResult,
    artifactId?: string,
    target?: string
  ): string {
    const lines: string[] = [];

    // Header
    lines.push(`[${toolName.toUpperCase()} OUTPUT - MASKED]`);
    if (target) lines.push(`Target: ${target}`);
    lines.push('');

    // Summary
    lines.push('## Summary');
    lines.push(extraction.summary);
    lines.push('');

    // Key findings
    if (extraction.findings.length > 0) {
      lines.push('## Key Findings');
      for (const finding of extraction.findings.slice(0, 10)) {
        const severityIcon = this.getSeverityIcon(finding.severity);
        lines.push(`${severityIcon} [${finding.severity.toUpperCase()}] ${finding.title}`);
        if (this.maskingConfig.includeEvidenceInSummary && finding.evidence.length > 0) {
          const evidence = finding.evidence[0].slice(0, 100);
          lines.push(`   Evidence: ${evidence}${finding.evidence[0].length > 100 ? '...' : ''}`);
        }
      }
      if (extraction.findings.length > 10) {
        lines.push(`   ... and ${extraction.findings.length - 10} more findings`);
      }
      lines.push('');
    }

    // Artifact reference
    if (artifactId) {
      lines.push('## Full Output');
      if (this.maskingConfig.artifactRefFormat === 'path') {
        lines.push(`Full output stored at: artifacts/${artifactId}`);
      } else {
        lines.push(`Artifact ID: ${artifactId}`);
      }
      lines.push('Use `read_artifact(id)` to retrieve full content if needed.');
    }

    return lines.join('\n');
  }

  /**
   * Store output as artifact
   */
  private storeArtifact(content: string, type: string): string {
    const id = `${type}-${uuidv4().slice(0, 8)}`;
    this.artifactStore.set(id, content);
    return id;
  }

  /**
   * Retrieve artifact by ID
   */
  getArtifact(id: string): string | undefined {
    return this.artifactStore.get(id);
  }

  // ==========================================================================
  // Context Segment Management
  // ==========================================================================

  /**
   * Add scope to context
   */
  addScope(scope: EngagementScope): void {
    const content = this.formatScope(scope);
    this.windowManager.addSegment('scope', content, 9);
  }

  /**
   * Add finding to context
   */
  addFinding(finding: KeyFinding): void {
    this.findingsCache.push(finding);
    const content = this.formatFinding(finding);
    const priority = this.findingPriority(finding);
    this.windowManager.addSegment('finding', content, priority);
  }

  /**
   * Add agent reasoning to context
   */
  addReasoning(agent: string, reasoning: string): void {
    const content = `[${agent}] ${reasoning}`;
    this.windowManager.addSegment('agent_reasoning', content, 5);
  }

  /**
   * Add conversation turn to context
   */
  addConversation(role: 'user' | 'assistant', content: string): void {
    const formatted = `[${role.toUpperCase()}] ${content}`;
    this.windowManager.addSegment('conversation', formatted, 2);
  }

  // ==========================================================================
  // Context Reconstruction
  // ==========================================================================

  /**
   * Generate a context snapshot for agent prompts
   *
   * Produces a compact summary of current state
   */
  generateSnapshot(): ContextSnapshot {
    const scopeSegments = this.windowManager.getSegmentsByType('scope');
    const findingSegments = this.windowManager.getSegmentsByType('finding');
    const recentSegments = this.getRecentSegments(5);

    const snapshot: ContextSnapshot = {
      scope: scopeSegments.map((s) => s.content).join('\n') || 'No scope defined',
      findings: this.summarizeFindings(),
      sessions: this.summarizeSessions(),
      recentActivity: recentSegments.map((s) => s.content).join('\n'),
      totalTokens: this.windowManager.getTokenUsage().current,
    };

    return snapshot;
  }

  /**
   * Generate context string for agent system prompt
   */
  generateAgentContext(): string {
    const snapshot = this.generateSnapshot();
    const usage = this.windowManager.getTokenUsage();

    const lines: string[] = [
      '=== ENGAGEMENT CONTEXT ===',
      '',
      '## Scope',
      snapshot.scope,
      '',
      '## Key Findings',
      snapshot.findings,
      '',
      '## Active Sessions',
      snapshot.sessions,
      '',
      '## Recent Activity',
      snapshot.recentActivity,
      '',
      `[Context: ${usage.current}/${usage.max} tokens (${(usage.percentage * 100).toFixed(1)}%)]`,
    ];

    return lines.join('\n');
  }

  /**
   * Get recent segments across all types
   */
  private getRecentSegments(count: number): ContextSegment[] {
    const window = this.windowManager.getWindow();
    return window.segments
      .slice()
      .sort((a, b) => new Date(b.created).getTime() - new Date(a.created).getTime())
      .slice(0, count);
  }

  /**
   * Summarize findings for context
   */
  private summarizeFindings(): string {
    if (this.findingsCache.length === 0) {
      return 'No findings yet.';
    }

    const bySeverity = {
      critical: this.findingsCache.filter((f) => f.severity === 'critical'),
      high: this.findingsCache.filter((f) => f.severity === 'high'),
      medium: this.findingsCache.filter((f) => f.severity === 'medium'),
      low: this.findingsCache.filter((f) => f.severity === 'low'),
      info: this.findingsCache.filter((f) => f.severity === 'info'),
    };

    const lines: string[] = [
      `Total: ${this.findingsCache.length} findings`,
    ];

    // Show critical and high findings in detail
    for (const finding of [...bySeverity.critical, ...bySeverity.high].slice(0, 5)) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.title}`);
    }

    // Summary for others
    const otherCount = bySeverity.medium.length + bySeverity.low.length + bySeverity.info.length;
    if (otherCount > 0) {
      lines.push(`- ${otherCount} additional findings (medium/low/info)`);
    }

    return lines.join('\n');
  }

  /**
   * Summarize sessions for context
   */
  private summarizeSessions(): string {
    // This would integrate with SessionManager
    // For now, return placeholder
    return 'No active sessions tracked in context.';
  }

  // ==========================================================================
  // Utility Methods
  // ==========================================================================

  private formatScope(scope: EngagementScope): string {
    const lines: string[] = [
      `Engagement: ${scope.name}`,
      '',
      'Authorized Targets:',
    ];

    for (const cidr of scope.cidrs) {
      lines.push(`  - ${cidr.network}${cidr.description ? ` (${cidr.description})` : ''}`);
    }

    for (const domain of scope.domains) {
      lines.push(`  - ${domain.pattern}${domain.description ? ` (${domain.description})` : ''}`);
    }

    if (scope.excludedIPs.length > 0 || scope.excludedDomains.length > 0) {
      lines.push('');
      lines.push('Exclusions:');
      for (const ip of scope.excludedIPs) {
        lines.push(`  - ${ip}`);
      }
      for (const domain of scope.excludedDomains) {
        lines.push(`  - ${domain}`);
      }
    }

    return lines.join('\n');
  }

  private formatFinding(finding: KeyFinding): string {
    const lines: string[] = [
      `[${finding.severity.toUpperCase()}] ${finding.title}`,
      `Type: ${finding.type} | Source: ${finding.source}`,
      finding.description,
    ];

    if (finding.relatedTargets.length > 0) {
      lines.push(`Targets: ${finding.relatedTargets.slice(0, 3).join(', ')}`);
    }

    return lines.join('\n');
  }

  private findingPriority(finding: KeyFinding): number {
    switch (finding.severity) {
      case 'critical':
        return 8;
      case 'high':
        return 7;
      case 'medium':
        return 6;
      case 'low':
        return 5;
      case 'info':
        return 4;
      default:
        return 4;
    }
  }

  private getSeverityIcon(severity: KeyFinding['severity']): string {
    switch (severity) {
      case 'critical':
        return '[!]';
      case 'high':
        return '[H]';
      case 'medium':
        return '[M]';
      case 'low':
        return '[L]';
      case 'info':
        return '[i]';
      default:
        return '[-]';
    }
  }

  private estimateTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }

  // ==========================================================================
  // State Management
  // ==========================================================================

  /**
   * Export context state for persistence
   */
  export(): { window: ContextWindow; findings: KeyFinding[]; artifacts: [string, string][] } {
    return {
      window: this.windowManager.export(),
      findings: this.findingsCache,
      artifacts: Array.from(this.artifactStore.entries()),
    };
  }

  /**
   * Import context state from persistence
   */
  import(state: {
    window: ContextWindow;
    findings: KeyFinding[];
    artifacts: [string, string][];
  }): void {
    this.windowManager.import(state.window);
    this.findingsCache = state.findings;
    this.artifactStore = new Map(state.artifacts);
  }

  /**
   * Clear all context
   */
  clear(): void {
    this.windowManager = createWindowManager();
    this.findingsCache = [];
    this.artifactStore.clear();
  }

  /**
   * Get context statistics
   */
  getStats(): {
    tokens: { current: number; max: number; percentage: number };
    findings: number;
    artifacts: number;
    segments: number;
  } {
    const tokenUsage = this.windowManager.getTokenUsage();
    return {
      tokens: tokenUsage,
      findings: this.findingsCache.length,
      artifacts: this.artifactStore.size,
      segments: this.windowManager.getWindow().segments.length,
    };
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new context manager
 */
export function createContextManager(
  windowConfig?: Partial<WindowConfig>,
  maskingConfig?: Partial<MaskingConfig>
): ContextManager {
  return new ContextManager(windowConfig, maskingConfig);
}

/**
 * Create context manager optimized for HTB engagements
 */
export function createHTBContextManager(): ContextManager {
  return new ContextManager(
    {
      maxTokens: 80000,      // Conservative for HTB
      compactionThreshold: 0.80,
      targetAfterCompaction: 0.55,
    },
    {
      minOutputLengthToMask: 500,
      maxUnmaskedToolOutput: 1500,
      maxSummaryLength: 400,
      includeEvidenceInSummary: true,
    }
  );
}
