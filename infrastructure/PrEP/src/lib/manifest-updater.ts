/**
 * Agent Opulence - Manifest Integration Hooks
 *
 * Maintains the engagement manifest document.
 * Integrates with tool outputs to update state.
 *
 * Key Features:
 * - Real-time manifest updates
 * - Timeline tracking
 * - Artifact registration
 * - Tool output processing hooks
 */

import {
  EngagementManifest,
  EngagementPhase,
  EngagementScope,
  StickySession,
  MSFSession,
  SliverBeacon,
  KeyFinding,
  ArtifactReference,
  TimelineEntry,
  ToolCallEvent,
  Result,
} from '../types';
import { SessionManager } from './session-manager';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

// ============================================================================
// Manifest File Management
// ============================================================================

const MANIFEST_FILENAME = 'manifest.yaml';
const MANIFEST_JSON_FILENAME = 'manifest.json';

/**
 * Load manifest from file
 */
export async function loadManifest(manifestDir: string): Promise<EngagementManifest | null> {
  try {
    const jsonPath = path.join(manifestDir, MANIFEST_JSON_FILENAME);
    const content = await fs.readFile(jsonPath, 'utf-8');
    return JSON.parse(content) as EngagementManifest;
  } catch {
    return null;
  }
}

/**
 * Save manifest to file (both JSON and YAML)
 */
export async function saveManifest(manifest: EngagementManifest, manifestDir: string): Promise<void> {
  await fs.mkdir(manifestDir, { recursive: true });

  // Save JSON
  const jsonPath = path.join(manifestDir, MANIFEST_JSON_FILENAME);
  await fs.writeFile(jsonPath, JSON.stringify(manifest, null, 2));

  // Save YAML (simplified format)
  const yamlPath = path.join(manifestDir, MANIFEST_FILENAME);
  await fs.writeFile(yamlPath, convertToYAML(manifest));
}

/**
 * Simple YAML conversion (for human-readable manifest)
 */
function convertToYAML(manifest: EngagementManifest): string {
  const lines: string[] = [];

  lines.push(`# Agent Opulence Engagement Manifest`);
  lines.push(`# Generated: ${new Date().toISOString()}`);
  lines.push(`version: "${manifest.version}"`);
  lines.push(``);

  // Engagement info
  lines.push(`engagement:`);
  lines.push(`  id: "${manifest.engagement.id}"`);
  lines.push(`  name: "${manifest.engagement.name}"`);
  lines.push(`  type: "${manifest.engagement.type}"`);
  lines.push(`  started: "${manifest.engagement.started}"`);
  lines.push(`  status: "${manifest.engagement.status}"`);
  lines.push(``);

  // Scope summary
  lines.push(`scope:`);
  lines.push(`  cidrs:`);
  for (const cidr of manifest.scope.cidrs) {
    lines.push(`    - network: "${cidr.network}"`);
    if (cidr.description) lines.push(`      description: "${cidr.description}"`);
  }
  lines.push(`  domains:`);
  for (const domain of manifest.scope.domains) {
    lines.push(`    - pattern: "${domain.pattern}"`);
    if (domain.description) lines.push(`      description: "${domain.description}"`);
  }
  lines.push(``);

  // Sessions
  lines.push(`sessions:`);
  lines.push(`  msf_count: ${manifest.sessions.msf.length}`);
  lines.push(`  sliver_count: ${manifest.sessions.sliver.length}`);
  lines.push(``);

  // Findings summary
  lines.push(`findings:`);
  lines.push(`  total: ${manifest.findings.length}`);
  const bySeverity = {
    critical: manifest.findings.filter((f) => f.severity === 'critical').length,
    high: manifest.findings.filter((f) => f.severity === 'high').length,
    medium: manifest.findings.filter((f) => f.severity === 'medium').length,
    low: manifest.findings.filter((f) => f.severity === 'low').length,
    info: manifest.findings.filter((f) => f.severity === 'info').length,
  };
  lines.push(`  by_severity:`);
  lines.push(`    critical: ${bySeverity.critical}`);
  lines.push(`    high: ${bySeverity.high}`);
  lines.push(`    medium: ${bySeverity.medium}`);
  lines.push(`    low: ${bySeverity.low}`);
  lines.push(`    info: ${bySeverity.info}`);
  lines.push(``);

  // Artifacts
  lines.push(`artifacts:`);
  lines.push(`  count: ${manifest.artifacts.length}`);
  lines.push(``);

  // Timeline (last 10 entries)
  lines.push(`timeline:`);
  const recentTimeline = manifest.timeline.slice(-10);
  for (const entry of recentTimeline) {
    lines.push(`  - timestamp: "${entry.timestamp}"`);
    lines.push(`    phase: "${entry.phase}"`);
    lines.push(`    agent: "${entry.agent}"`);
    lines.push(`    action: "${entry.action}"`);
  }

  return lines.join('\n');
}

// ============================================================================
// Manifest Updater Class
// ============================================================================

export class ManifestUpdater {
  private manifest: EngagementManifest;
  private manifestDir: string;
  private sessionManager: SessionManager;
  private autoSaveEnabled: boolean = true;
  private pendingUpdates: number = 0;
  private saveDebounceTimer: NodeJS.Timeout | null = null;

  constructor(
    manifest: EngagementManifest,
    manifestDir: string,
    sessionManager: SessionManager
  ) {
    this.manifest = manifest;
    this.manifestDir = manifestDir;
    this.sessionManager = sessionManager;
  }

  /**
   * Get the current manifest
   */
  getManifest(): EngagementManifest {
    return this.manifest;
  }

  /**
   * Update engagement phase
   */
  async setPhase(phase: EngagementPhase, agent: string): Promise<void> {
    this.manifest.engagement.status = phase;

    this.addTimelineEntry({
      timestamp: new Date().toISOString(),
      phase,
      agent,
      action: `Phase changed to ${phase}`,
      details: `Engagement phase updated from previous state`,
    });

    await this.sessionManager.setPhase(phase);
    await this.scheduleSave();
  }

  /**
   * Update scope
   */
  async updateScope(scope: EngagementScope, agent: string): Promise<void> {
    this.manifest.scope = scope;

    this.addTimelineEntry({
      timestamp: new Date().toISOString(),
      phase: this.manifest.engagement.status,
      agent,
      action: 'Scope updated',
      details: `Scope modified: ${scope.cidrs.length} CIDRs, ${scope.domains.length} domains`,
    });

    await this.sessionManager.updateScope(scope);
    await this.scheduleSave();
  }

  // ==========================================================================
  // Session Management
  // ==========================================================================

  /**
   * Register MSF session from tool output
   */
  async registerMSFSession(session: MSFSession, agent: string): Promise<void> {
    // Add to manifest
    const existing = this.manifest.sessions.msf.findIndex(
      (s) => s.sessionId === session.sessionId
    );
    if (existing >= 0) {
      this.manifest.sessions.msf[existing] = session;
    } else {
      this.manifest.sessions.msf.push(session);
    }

    // Update session manager
    await this.sessionManager.registerMSFSession(session);

    // Add timeline entry
    this.addTimelineEntry({
      timestamp: new Date().toISOString(),
      phase: this.manifest.engagement.status,
      agent,
      action: `MSF session ${session.sessionId} established`,
      details: `${session.type} session on ${session.targetHost}:${session.targetPort}`,
    });

    await this.scheduleSave();
  }

  /**
   * Remove MSF session
   */
  async removeMSFSession(sessionId: number, agent: string, reason: string): Promise<void> {
    this.manifest.sessions.msf = this.manifest.sessions.msf.filter(
      (s) => s.sessionId !== sessionId
    );

    await this.sessionManager.removeMSFSession(sessionId);

    this.addTimelineEntry({
      timestamp: new Date().toISOString(),
      phase: this.manifest.engagement.status,
      agent,
      action: `MSF session ${sessionId} closed`,
      details: reason,
    });

    await this.scheduleSave();
  }

  /**
   * Register Sliver beacon
   */
  async registerSliverBeacon(beacon: SliverBeacon, agent: string): Promise<void> {
    const existing = this.manifest.sessions.sliver.findIndex(
      (b) => b.beaconId === beacon.beaconId
    );
    if (existing >= 0) {
      this.manifest.sessions.sliver[existing] = beacon;
    } else {
      this.manifest.sessions.sliver.push(beacon);
    }

    await this.sessionManager.registerSliverBeacon(beacon);

    this.addTimelineEntry({
      timestamp: new Date().toISOString(),
      phase: this.manifest.engagement.status,
      agent,
      action: `Sliver beacon ${beacon.name} established`,
      details: `Beacon on ${beacon.targetHost} (${beacon.os}/${beacon.arch})`,
    });

    await this.scheduleSave();
  }

  /**
   * Remove Sliver beacon
   */
  async removeSliverBeacon(beaconId: string, agent: string, reason: string): Promise<void> {
    this.manifest.sessions.sliver = this.manifest.sessions.sliver.filter(
      (b) => b.beaconId !== beaconId
    );

    await this.sessionManager.removeSliverBeacon(beaconId);

    this.addTimelineEntry({
      timestamp: new Date().toISOString(),
      phase: this.manifest.engagement.status,
      agent,
      action: `Sliver beacon ${beaconId} removed`,
      details: reason,
    });

    await this.scheduleSave();
  }

  // ==========================================================================
  // Findings Management
  // ==========================================================================

  /**
   * Add a key finding
   */
  async addFinding(finding: KeyFinding, agent: string): Promise<void> {
    // Ensure unique ID
    if (!finding.id) {
      finding.id = uuidv4();
    }

    this.manifest.findings.push(finding);
    await this.sessionManager.addFinding(finding);

    this.addTimelineEntry({
      timestamp: new Date().toISOString(),
      phase: this.manifest.engagement.status,
      agent,
      action: `Finding: ${finding.title}`,
      details: `${finding.severity.toUpperCase()} - ${finding.type}`,
    });

    await this.scheduleSave();
  }

  /**
   * Get findings by type
   */
  getFindingsByType(type: KeyFinding['type']): KeyFinding[] {
    return this.manifest.findings.filter((f) => f.type === type);
  }

  /**
   * Get findings by severity
   */
  getFindingsBySeverity(severity: KeyFinding['severity']): KeyFinding[] {
    return this.manifest.findings.filter((f) => f.severity === severity);
  }

  // ==========================================================================
  // Artifact Management
  // ==========================================================================

  /**
   * Register an artifact
   */
  async registerArtifact(
    artifactPath: string,
    type: string,
    tags: string[],
    agent: string
  ): Promise<ArtifactReference> {
    // Get file info
    const stats = await fs.stat(artifactPath);
    const content = await fs.readFile(artifactPath);
    const checksum = crypto.createHash('sha256').update(content).digest('hex');

    const artifact: ArtifactReference = {
      id: uuidv4(),
      type,
      path: artifactPath,
      created: new Date().toISOString(),
      size: stats.size,
      checksum,
      tags,
    };

    this.manifest.artifacts.push(artifact);

    this.addTimelineEntry({
      timestamp: new Date().toISOString(),
      phase: this.manifest.engagement.status,
      agent,
      action: `Artifact registered: ${type}`,
      details: `${artifactPath} (${stats.size} bytes)`,
      artifactRefs: [artifact.id],
    });

    await this.scheduleSave();
    return artifact;
  }

  /**
   * Get artifact by ID
   */
  getArtifact(id: string): ArtifactReference | undefined {
    return this.manifest.artifacts.find((a) => a.id === id);
  }

  /**
   * Get artifacts by type
   */
  getArtifactsByType(type: string): ArtifactReference[] {
    return this.manifest.artifacts.filter((a) => a.type === type);
  }

  /**
   * Get artifacts by tag
   */
  getArtifactsByTag(tag: string): ArtifactReference[] {
    return this.manifest.artifacts.filter((a) => a.tags.includes(tag));
  }

  // ==========================================================================
  // Timeline Management
  // ==========================================================================

  /**
   * Add timeline entry
   */
  addTimelineEntry(entry: TimelineEntry): void {
    this.manifest.timeline.push(entry);
  }

  /**
   * Get recent timeline entries
   */
  getRecentTimeline(count: number = 10): TimelineEntry[] {
    return this.manifest.timeline.slice(-count);
  }

  /**
   * Get timeline for a phase
   */
  getTimelineByPhase(phase: EngagementPhase): TimelineEntry[] {
    return this.manifest.timeline.filter((e) => e.phase === phase);
  }

  // ==========================================================================
  // Tool Output Hooks
  // ==========================================================================

  /**
   * Process tool output and update manifest accordingly
   */
  async processToolOutput(
    event: ToolCallEvent,
    output: unknown,
    agent: string
  ): Promise<void> {
    const tool = event.tool.toLowerCase();
    const namespace = event.namespace || '';

    // Route to appropriate handler
    if (namespace.includes('metasploit') || namespace.includes('msf')) {
      await this.processMSFOutput(tool, event.input, output, agent);
    } else if (namespace.includes('sliver')) {
      await this.processSliverOutput(tool, event.input, output, agent);
    } else if (namespace.includes('hexstrike') || ['nmap', 'nuclei', 'httpx'].includes(tool)) {
      await this.processReconOutput(tool, event.input, output, agent);
    }
  }

  private async processMSFOutput(
    tool: string,
    input: Record<string, unknown>,
    output: unknown,
    agent: string
  ): Promise<void> {
    // Parse MSF session creation
    if (tool.includes('exploit') && output && typeof output === 'object') {
      const result = output as Record<string, unknown>;
      if (result.session_id || result.sessionId) {
        const sessionId = (result.session_id || result.sessionId) as number;
        const session: MSFSession = {
          sessionId,
          type: (result.type as 'meterpreter' | 'shell') || 'shell',
          targetHost: (input.rhost || input.target || '') as string,
          targetPort: (input.rport || 0) as number,
          established: new Date().toISOString(),
        };
        await this.registerMSFSession(session, agent);
      }
    }
  }

  private async processSliverOutput(
    tool: string,
    input: Record<string, unknown>,
    output: unknown,
    agent: string
  ): Promise<void> {
    // Parse Sliver beacon creation
    if (tool.includes('beacon') && output && typeof output === 'object') {
      const result = output as Record<string, unknown>;
      if (result.beacon_id || result.beaconId) {
        const beacon: SliverBeacon = {
          beaconId: (result.beacon_id || result.beaconId) as string,
          name: (result.name || 'unnamed') as string,
          targetHost: (input.host || '') as string,
          os: (result.os || 'unknown') as string,
          arch: (result.arch || 'unknown') as string,
          established: new Date().toISOString(),
          interval: (result.interval || 60) as number,
          jitter: (result.jitter || 30) as number,
        };
        await this.registerSliverBeacon(beacon, agent);
      }
    }
  }

  private async processReconOutput(
    tool: string,
    input: Record<string, unknown>,
    output: unknown,
    agent: string
  ): Promise<void> {
    // Timeline entry for recon activity
    const target = (input.target || input.host || 'unknown') as string;
    this.addTimelineEntry({
      timestamp: new Date().toISOString(),
      phase: this.manifest.engagement.status,
      agent,
      action: `${tool} scan completed`,
      details: `Target: ${target}`,
    });
    await this.scheduleSave();
  }

  // ==========================================================================
  // Persistence
  // ==========================================================================

  /**
   * Save manifest to disk
   */
  async save(): Promise<void> {
    await saveManifest(this.manifest, this.manifestDir);
    this.pendingUpdates = 0;
  }

  /**
   * Schedule a debounced save
   */
  private async scheduleSave(): Promise<void> {
    if (!this.autoSaveEnabled) return;

    this.pendingUpdates++;

    // Debounce saves to avoid excessive disk I/O
    if (this.saveDebounceTimer) {
      clearTimeout(this.saveDebounceTimer);
    }

    this.saveDebounceTimer = setTimeout(async () => {
      await this.save();
    }, 1000);
  }

  /**
   * Enable/disable auto-save
   */
  setAutoSave(enabled: boolean): void {
    this.autoSaveEnabled = enabled;
  }

  /**
   * Force immediate save
   */
  async forceSave(): Promise<void> {
    if (this.saveDebounceTimer) {
      clearTimeout(this.saveDebounceTimer);
      this.saveDebounceTimer = null;
    }
    await this.save();
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new empty manifest
 */
export function createEmptyManifest(
  engagementId: string,
  name: string,
  type: string,
  scope: EngagementScope
): EngagementManifest {
  return {
    version: '1.0.0',
    engagement: {
      id: engagementId,
      name,
      type,
      started: new Date().toISOString(),
      status: 'init',
    },
    scope,
    sessions: {
      sticky: {
        id: uuidv4(),
        engagementId,
        created: new Date().toISOString(),
        lastActive: new Date().toISOString(),
        scope,
        phase: 'init',
        msfSessions: [],
        sliverBeacons: [],
        contextWindow: {
          maxTokens: 100000,
          currentTokens: 0,
          segments: [],
          lastCompaction: new Date().toISOString(),
          compressionRatio: 1.0,
        },
        keyFindings: [],
      },
      msf: [],
      sliver: [],
    },
    findings: [],
    artifacts: [],
    timeline: [
      {
        timestamp: new Date().toISOString(),
        phase: 'init',
        agent: 'system',
        action: 'Engagement initialized',
        details: `Created engagement: ${name}`,
      },
    ],
  };
}

/**
 * Create a ManifestUpdater instance
 */
export async function createManifestUpdater(
  manifestDir: string,
  sessionManager: SessionManager
): Promise<ManifestUpdater> {
  // Try to load existing manifest
  let manifest = await loadManifest(manifestDir);

  if (!manifest) {
    // Create default manifest
    const session = sessionManager.getCurrentSession();
    if (!session) {
      throw new Error('No active session for manifest creation');
    }

    manifest = createEmptyManifest(
      session.engagementId,
      'New Engagement',
      'generic',
      session.scope
    );
    await saveManifest(manifest, manifestDir);
  }

  return new ManifestUpdater(manifest, manifestDir, sessionManager);
}
