/**
 * Agent Opulence - Rolling Window Manager
 *
 * Manages context window with priority-based eviction.
 * Implements rolling window with compaction.
 *
 * Key Features:
 * - Priority-based segment management
 * - Automatic compaction when near limit
 * - Token counting and tracking
 * - Segment merging for efficiency
 */

import {
  ContextWindow,
  ContextSegment,
  ContextSegmentType,
} from '../types';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// Configuration
// ============================================================================

export interface WindowConfig {
  maxTokens: number;
  compactionThreshold: number;  // Trigger compaction at this % of max
  targetAfterCompaction: number; // Target % after compaction
  minSegmentPriority: number;   // Don't evict segments above this priority
}

const DEFAULT_CONFIG: WindowConfig = {
  maxTokens: 100000,
  compactionThreshold: 0.85,    // Compact at 85%
  targetAfterCompaction: 0.60,  // Target 60% after compaction
  minSegmentPriority: 8,        // Keep priority 8+ segments
};

// Priority levels for segment types
const TYPE_PRIORITIES: Record<ContextSegmentType, number> = {
  system: 10,           // Never evict
  scope: 9,             // Rarely evict
  finding: 7,           // High priority
  agent_reasoning: 5,   // Medium priority
  artifact_ref: 4,      // Can evict, can re-fetch
  tool_output: 3,       // Low priority, compress first
  conversation: 2,      // Oldest evicted first
};

// ============================================================================
// Window Manager Class
// ============================================================================

export class WindowManager {
  private window: ContextWindow;
  private config: WindowConfig;

  constructor(window?: ContextWindow, config?: Partial<WindowConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.window = window || this.createEmptyWindow();
  }

  /**
   * Get the current window state
   */
  getWindow(): ContextWindow {
    return this.window;
  }

  /**
   * Get current token usage
   */
  getTokenUsage(): { current: number; max: number; percentage: number } {
    return {
      current: this.window.currentTokens,
      max: this.window.maxTokens,
      percentage: this.window.currentTokens / this.window.maxTokens,
    };
  }

  /**
   * Add a new segment to the window
   */
  addSegment(
    type: ContextSegmentType,
    content: string,
    priority?: number
  ): ContextSegment {
    const tokens = this.estimateTokens(content);
    const segment: ContextSegment = {
      id: uuidv4(),
      type,
      priority: priority ?? TYPE_PRIORITIES[type],
      tokens,
      created: new Date().toISOString(),
      content,
      masked: false,
    };

    this.window.segments.push(segment);
    this.window.currentTokens += tokens;

    // Check if compaction needed
    if (this.needsCompaction()) {
      this.compact();
    }

    return segment;
  }

  /**
   * Add a masked segment (already compressed)
   */
  addMaskedSegment(
    type: ContextSegmentType,
    maskedContent: string,
    originalTokens: number,
    priority?: number
  ): ContextSegment {
    const tokens = this.estimateTokens(maskedContent);
    const segment: ContextSegment = {
      id: uuidv4(),
      type,
      priority: priority ?? TYPE_PRIORITIES[type],
      tokens,
      created: new Date().toISOString(),
      content: maskedContent,
      masked: true,
      originalTokens,
    };

    this.window.segments.push(segment);
    this.window.currentTokens += tokens;

    if (this.needsCompaction()) {
      this.compact();
    }

    return segment;
  }

  /**
   * Update an existing segment
   */
  updateSegment(id: string, content: string): boolean {
    const segment = this.window.segments.find((s) => s.id === id);
    if (!segment) return false;

    const oldTokens = segment.tokens;
    const newTokens = this.estimateTokens(content);

    segment.content = content;
    segment.tokens = newTokens;
    this.window.currentTokens += newTokens - oldTokens;

    if (this.needsCompaction()) {
      this.compact();
    }

    return true;
  }

  /**
   * Remove a segment
   */
  removeSegment(id: string): boolean {
    const index = this.window.segments.findIndex((s) => s.id === id);
    if (index === -1) return false;

    const segment = this.window.segments[index];
    this.window.currentTokens -= segment.tokens;
    this.window.segments.splice(index, 1);

    return true;
  }

  /**
   * Get segments by type
   */
  getSegmentsByType(type: ContextSegmentType): ContextSegment[] {
    return this.window.segments.filter((s) => s.type === type);
  }

  /**
   * Check if compaction is needed
   */
  needsCompaction(): boolean {
    const usage = this.window.currentTokens / this.window.maxTokens;
    return usage >= this.config.compactionThreshold;
  }

  /**
   * Perform compaction to reduce token usage
   */
  compact(): void {
    const targetTokens = this.window.maxTokens * this.config.targetAfterCompaction;
    let tokensToFree = this.window.currentTokens - targetTokens;

    if (tokensToFree <= 0) return;

    // Sort segments by priority (ascending) then age (oldest first)
    const candidates = [...this.window.segments]
      .filter((s) => s.priority < this.config.minSegmentPriority)
      .sort((a, b) => {
        if (a.priority !== b.priority) return a.priority - b.priority;
        return new Date(a.created).getTime() - new Date(b.created).getTime();
      });

    const toRemove: string[] = [];
    let freedTokens = 0;

    for (const segment of candidates) {
      if (freedTokens >= tokensToFree) break;

      toRemove.push(segment.id);
      freedTokens += segment.tokens;
    }

    // Remove selected segments
    for (const id of toRemove) {
      this.removeSegment(id);
    }

    // Update compaction stats
    this.window.lastCompaction = new Date().toISOString();
    this.window.compressionRatio = this.window.currentTokens / this.window.maxTokens;
  }

  /**
   * Merge similar segments to save tokens
   */
  mergeSegments(type: ContextSegmentType): void {
    const segments = this.getSegmentsByType(type);
    if (segments.length <= 1) return;

    // Sort by creation time
    segments.sort(
      (a, b) => new Date(a.created).getTime() - new Date(b.created).getTime()
    );

    // Merge consecutive segments of same type
    const merged: ContextSegment[] = [];
    let current = segments[0];

    for (let i = 1; i < segments.length; i++) {
      const next = segments[i];

      // Check if can merge (same priority, total tokens reasonable)
      if (
        current.priority === next.priority &&
        current.tokens + next.tokens < 5000
      ) {
        // Merge
        current = {
          ...current,
          content: `${current.content}\n---\n${next.content}`,
          tokens: current.tokens + next.tokens,
        };
        // Mark for removal
        this.removeSegment(next.id);
      } else {
        merged.push(current);
        current = next;
      }
    }
    merged.push(current);

    // Update merged segments
    for (const segment of merged) {
      const existing = this.window.segments.find((s) => s.id === segment.id);
      if (existing) {
        existing.content = segment.content;
        existing.tokens = segment.tokens;
      }
    }
  }

  /**
   * Get summary of window contents
   */
  getSummary(): string {
    const byType = new Map<ContextSegmentType, { count: number; tokens: number }>();

    for (const segment of this.window.segments) {
      const current = byType.get(segment.type) || { count: 0, tokens: 0 };
      byType.set(segment.type, {
        count: current.count + 1,
        tokens: current.tokens + segment.tokens,
      });
    }

    const lines: string[] = [
      `Context Window: ${this.window.currentTokens}/${this.window.maxTokens} tokens (${(
        (this.window.currentTokens / this.window.maxTokens) *
        100
      ).toFixed(1)}%)`,
      '',
    ];

    for (const [type, stats] of byType) {
      lines.push(`  ${type}: ${stats.count} segments, ${stats.tokens} tokens`);
    }

    return lines.join('\n');
  }

  /**
   * Export window for serialization
   */
  export(): ContextWindow {
    return { ...this.window };
  }

  /**
   * Import window from serialized state
   */
  import(window: ContextWindow): void {
    this.window = window;
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  private createEmptyWindow(): ContextWindow {
    return {
      maxTokens: this.config.maxTokens,
      currentTokens: 0,
      segments: [],
      lastCompaction: new Date().toISOString(),
      compressionRatio: 0,
    };
  }

  private estimateTokens(text: string): number {
    // Rough estimation: ~4 characters per token
    // This is a simplification; real token counting would use tiktoken
    return Math.ceil(text.length / 4);
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new window manager with default config
 */
export function createWindowManager(
  config?: Partial<WindowConfig>
): WindowManager {
  return new WindowManager(undefined, config);
}

/**
 * Create a window manager from existing state
 */
export function restoreWindowManager(
  window: ContextWindow,
  config?: Partial<WindowConfig>
): WindowManager {
  return new WindowManager(window, config);
}
