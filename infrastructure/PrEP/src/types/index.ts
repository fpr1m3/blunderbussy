/**
 * Agent Opulence - PrEP Type Definitions
 *
 * Core types for the Personal AI Infrastructure plugin layer.
 * Handles scope validation, policy enforcement, and context management.
 */

// ============================================================================
// Scope Types
// ============================================================================

/**
 * CIDR range specification for network scope
 */
export interface CIDRRange {
  network: string;      // e.g., "10.129.0.0/16"
  description?: string; // e.g., "HTB VPN Range"
}

/**
 * Domain pattern for scope matching
 * Supports wildcards: *.example.com
 */
export interface DomainPattern {
  pattern: string;      // e.g., "*.htb" or "target.htb"
  description?: string;
}

/**
 * Complete scope definition for an engagement
 */
export interface EngagementScope {
  id: string;
  name: string;
  created: string;
  updated: string;

  // Network boundaries
  cidrs: CIDRRange[];
  domains: DomainPattern[];

  // Explicit exclusions
  excludedIPs: string[];
  excludedDomains: string[];

  // Expansion state
  pendingExpansions: ScopeExpansionRequest[];
  expansionHistory: ScopeExpansionRecord[];
}

/**
 * Request to expand scope (requires human approval)
 */
export interface ScopeExpansionRequest {
  id: string;
  requestedAt: string;
  requestedBy: string;  // Agent name
  reason: string;

  // What's being requested
  type: 'cidr' | 'domain' | 'ip';
  value: string;

  // Context for decision
  discoveredVia: string;      // e.g., "DNS enumeration", "port scan"
  relatedFindings: string[];

  status: 'pending' | 'approved' | 'denied';
}

/**
 * Historical record of scope expansion
 */
export interface ScopeExpansionRecord {
  request: ScopeExpansionRequest;
  decidedAt: string;
  decidedBy: string;    // 'human' or 'auto'
  decision: 'approved' | 'denied';
  notes?: string;
}

/**
 * Result of scope validation check
 */
export interface ScopeValidationResult {
  inScope: boolean;
  target: string;
  matchedRule?: string;         // Which rule allowed/denied
  requiresExpansion: boolean;
  expansionRequestId?: string;  // If expansion was auto-requested
  reason: string;
}

// ============================================================================
// Policy Types
// ============================================================================

/**
 * Policy actions for namespace operations
 */
export type PolicyAction = 'ALLOW' | 'ASK' | 'DENY';

/**
 * Individual policy rule
 */
export interface PolicyRule {
  id: string;
  namespace: string;    // e.g., "mcp:metasploit:*"
  tool?: string;        // e.g., "exploit/*"
  action: PolicyAction;
  conditions?: PolicyCondition[];
  reason?: string;
}

/**
 * Conditional policy evaluation
 */
export interface PolicyCondition {
  field: string;        // e.g., "target", "payload_type"
  operator: 'equals' | 'contains' | 'matches' | 'in_scope';
  value: string | string[];
}

/**
 * Complete policy configuration
 */
export interface PolicyConfig {
  version: string;
  updated: string;

  // Default action when no rule matches
  defaultAction: PolicyAction;

  // Ordered rules (first match wins)
  rules: PolicyRule[];

  // Tool-specific overrides
  toolOverrides: Record<string, PolicyAction>;
}

/**
 * Result of policy evaluation
 */
export interface PolicyEvaluationResult {
  action: PolicyAction;
  matchedRule?: PolicyRule;
  needsHumanApproval: boolean;
  approvalPrompt?: string;
  denialReason?: string;
}

// ============================================================================
// Session Types
// ============================================================================

/**
 * Sticky session state for persistent engagement context
 */
export interface StickySession {
  id: string;
  engagementId: string;
  created: string;
  lastActive: string;

  // Current state
  scope: EngagementScope;
  phase: EngagementPhase;

  // Active tool sessions
  msfSessions: MSFSession[];
  sliverBeacons: SliverBeacon[];

  // Context window
  contextWindow: ContextWindow;

  // Findings accumulator
  keyFindings: KeyFinding[];
}

/**
 * Engagement phase tracking
 */
export type EngagementPhase =
  | 'init'
  | 'recon'
  | 'enumeration'
  | 'exploitation'
  | 'post-exploitation'
  | 'persistence'
  | 'cleanup'
  | 'complete';

/**
 * Metasploit session reference
 */
export interface MSFSession {
  sessionId: number;
  type: 'meterpreter' | 'shell';
  targetHost: string;
  targetPort: number;
  established: string;
  lastCheckin?: string;
}

/**
 * Sliver beacon reference
 */
export interface SliverBeacon {
  beaconId: string;
  name: string;
  targetHost: string;
  os: string;
  arch: string;
  established: string;
  interval: number;
  jitter: number;
}

// ============================================================================
// Context Management Types
// ============================================================================

/**
 * Rolling context window for token management
 */
export interface ContextWindow {
  maxTokens: number;
  currentTokens: number;

  // Segments with priority
  segments: ContextSegment[];

  // Compression state
  lastCompaction: string;
  compressionRatio: number;
}

/**
 * Individual context segment with priority
 */
export interface ContextSegment {
  id: string;
  type: ContextSegmentType;
  priority: number;       // 1-10, higher = keep longer
  tokens: number;
  created: string;

  // Content (may be masked)
  content: string;
  masked: boolean;
  originalTokens?: number;
}

/**
 * Types of context segments
 */
export type ContextSegmentType =
  | 'system'          // System prompts, always kept
  | 'scope'           // Scope definitions
  | 'finding'         // Key findings, high priority
  | 'tool_output'     // Raw tool output, can be compressed
  | 'agent_reasoning' // Agent thoughts, medium priority
  | 'artifact_ref'    // Reference to stored artifact
  | 'conversation';   // General conversation

/**
 * Key finding extracted from tool output
 */
export interface KeyFinding {
  id: string;
  type: FindingType;
  timestamp: string;
  source: string;       // Tool/agent that found it

  // Finding details
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';

  // Evidence
  evidence: string[];
  artifactRefs: string[];

  // Relationships
  relatedTargets: string[];
  relatedFindings: string[];
}

/**
 * Types of findings
 */
export type FindingType =
  | 'credential'
  | 'vulnerability'
  | 'service'
  | 'subdomain'
  | 'pivot_point'
  | 'persistence'
  | 'artifact'
  | 'note';

// ============================================================================
// Manifest Types
// ============================================================================

/**
 * Engagement manifest - the central state document
 */
export interface EngagementManifest {
  version: string;
  engagement: {
    id: string;
    name: string;
    type: string;         // e.g., "htb_machine", "pentest", "ctf"
    started: string;
    status: EngagementPhase;
  };

  scope: EngagementScope;

  sessions: {
    sticky: StickySession;
    msf: MSFSession[];
    sliver: SliverBeacon[];
  };

  findings: KeyFinding[];

  artifacts: ArtifactReference[];

  timeline: TimelineEntry[];
}

/**
 * Reference to stored artifact
 */
export interface ArtifactReference {
  id: string;
  type: string;           // e.g., "nmap_scan", "exploit_output"
  path: string;           // Path in artifact store
  created: string;
  size: number;
  checksum: string;
  tags: string[];
}

/**
 * Timeline entry for engagement tracking
 */
export interface TimelineEntry {
  timestamp: string;
  phase: EngagementPhase;
  agent: string;
  action: string;
  details: string;
  artifactRefs?: string[];
}

// ============================================================================
// Hook Types
// ============================================================================

/**
 * Tool call interception data
 */
export interface ToolCallEvent {
  tool: string;
  namespace?: string;
  input: Record<string, unknown>;
  timestamp: string;
  sessionId: string;
}

/**
 * Hook decision result
 */
export interface HookDecision {
  allow: boolean;
  modified?: boolean;
  modifiedInput?: Record<string, unknown>;
  reason: string;
  userPrompt?: string;
}

// ============================================================================
// Utility Types
// ============================================================================

/**
 * Result wrapper for operations that can fail
 */
export type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

/**
 * Async result type
 */
export type AsyncResult<T, E = Error> = Promise<Result<T, E>>;
