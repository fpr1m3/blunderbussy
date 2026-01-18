/**
 * Agent Opulence - Sticky Session Manager
 *
 * Maintains persistent engagement context across Claude sessions.
 * Handles session persistence, restoration, and state tracking.
 *
 * Key Features:
 * - Persistent storage of engagement state
 * - Tool session tracking (MSF, Sliver)
 * - Phase progression
 * - Automatic session recovery
 */

import {
  StickySession,
  EngagementScope,
  EngagementPhase,
  MSFSession,
  SliverBeacon,
  ContextWindow,
  KeyFinding,
  Result,
} from '../types';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs/promises';
import * as path from 'path';

// ============================================================================
// Session Storage
// ============================================================================

const DEFAULT_SESSION_DIR = '.opulence/sessions';
const CURRENT_SESSION_FILE = 'current.json';
const SESSION_EXTENSION = '.session.json';

/**
 * Session storage interface for persistence
 */
interface SessionStorage {
  save(session: StickySession): Promise<void>;
  load(sessionId: string): Promise<StickySession | null>;
  loadCurrent(): Promise<StickySession | null>;
  setCurrent(sessionId: string): Promise<void>;
  list(): Promise<string[]>;
  delete(sessionId: string): Promise<void>;
}

/**
 * File-based session storage implementation
 */
class FileSessionStorage implements SessionStorage {
  private baseDir: string;

  constructor(baseDir: string = DEFAULT_SESSION_DIR) {
    this.baseDir = baseDir;
  }

  async ensureDir(): Promise<void> {
    await fs.mkdir(this.baseDir, { recursive: true });
  }

  async save(session: StickySession): Promise<void> {
    await this.ensureDir();
    const filePath = path.join(this.baseDir, `${session.id}${SESSION_EXTENSION}`);
    await fs.writeFile(filePath, JSON.stringify(session, null, 2));
  }

  async load(sessionId: string): Promise<StickySession | null> {
    try {
      const filePath = path.join(this.baseDir, `${sessionId}${SESSION_EXTENSION}`);
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content) as StickySession;
    } catch {
      return null;
    }
  }

  async loadCurrent(): Promise<StickySession | null> {
    try {
      const currentPath = path.join(this.baseDir, CURRENT_SESSION_FILE);
      const content = await fs.readFile(currentPath, 'utf-8');
      const { sessionId } = JSON.parse(content);
      return this.load(sessionId);
    } catch {
      return null;
    }
  }

  async setCurrent(sessionId: string): Promise<void> {
    await this.ensureDir();
    const currentPath = path.join(this.baseDir, CURRENT_SESSION_FILE);
    await fs.writeFile(currentPath, JSON.stringify({ sessionId, updated: new Date().toISOString() }));
  }

  async list(): Promise<string[]> {
    try {
      await this.ensureDir();
      const files = await fs.readdir(this.baseDir);
      return files
        .filter((f) => f.endsWith(SESSION_EXTENSION))
        .map((f) => f.replace(SESSION_EXTENSION, ''));
    } catch {
      return [];
    }
  }

  async delete(sessionId: string): Promise<void> {
    const filePath = path.join(this.baseDir, `${sessionId}${SESSION_EXTENSION}`);
    await fs.unlink(filePath).catch(() => {});
  }
}

// ============================================================================
// Session Manager Class
// ============================================================================

export class SessionManager {
  private storage: SessionStorage;
  private currentSession: StickySession | null = null;
  private autoSaveInterval: NodeJS.Timeout | null = null;
  private dirty: boolean = false;

  constructor(storage?: SessionStorage) {
    this.storage = storage || new FileSessionStorage();
  }

  /**
   * Initialize the session manager
   * Attempts to restore the current session
   */
  async initialize(): Promise<StickySession | null> {
    this.currentSession = await this.storage.loadCurrent();
    if (this.currentSession) {
      this.currentSession.lastActive = new Date().toISOString();
      await this.save();
    }
    return this.currentSession;
  }

  /**
   * Create a new engagement session
   */
  async createSession(
    engagementId: string,
    scope: EngagementScope,
    setAsCurrent: boolean = true
  ): Promise<StickySession> {
    const session: StickySession = {
      id: uuidv4(),
      engagementId,
      created: new Date().toISOString(),
      lastActive: new Date().toISOString(),
      scope,
      phase: 'init',
      msfSessions: [],
      sliverBeacons: [],
      contextWindow: this.createEmptyContextWindow(),
      keyFindings: [],
    };

    await this.storage.save(session);

    if (setAsCurrent) {
      await this.storage.setCurrent(session.id);
      this.currentSession = session;
    }

    return session;
  }

  /**
   * Get the current active session
   */
  getCurrentSession(): StickySession | null {
    return this.currentSession;
  }

  /**
   * Switch to a different session
   */
  async switchSession(sessionId: string): Promise<Result<StickySession, Error>> {
    const session = await this.storage.load(sessionId);
    if (!session) {
      return { ok: false, error: new Error(`Session not found: ${sessionId}`) };
    }

    // Save current session before switching
    if (this.currentSession && this.dirty) {
      await this.save();
    }

    session.lastActive = new Date().toISOString();
    await this.storage.setCurrent(sessionId);
    this.currentSession = session;
    this.dirty = true;

    return { ok: true, value: session };
  }

  /**
   * Save the current session
   */
  async save(): Promise<void> {
    if (this.currentSession) {
      this.currentSession.lastActive = new Date().toISOString();
      await this.storage.save(this.currentSession);
      this.dirty = false;
    }
  }

  /**
   * Update the engagement phase
   */
  async setPhase(phase: EngagementPhase): Promise<void> {
    if (!this.currentSession) {
      throw new Error('No active session');
    }
    this.currentSession.phase = phase;
    this.dirty = true;
    await this.save();
  }

  /**
   * Get the current engagement phase
   */
  getPhase(): EngagementPhase {
    return this.currentSession?.phase || 'init';
  }

  /**
   * Update scope in current session
   */
  async updateScope(scope: EngagementScope): Promise<void> {
    if (!this.currentSession) {
      throw new Error('No active session');
    }
    this.currentSession.scope = scope;
    this.dirty = true;
    await this.save();
  }

  // ==========================================================================
  // MSF Session Management
  // ==========================================================================

  /**
   * Register a new Metasploit session
   */
  async registerMSFSession(session: MSFSession): Promise<void> {
    if (!this.currentSession) {
      throw new Error('No active session');
    }

    // Check if already registered
    const existing = this.currentSession.msfSessions.find(
      (s) => s.sessionId === session.sessionId
    );
    if (existing) {
      // Update existing
      Object.assign(existing, session);
    } else {
      this.currentSession.msfSessions.push(session);
    }

    this.dirty = true;
    await this.save();
  }

  /**
   * Remove a Metasploit session
   */
  async removeMSFSession(sessionId: number): Promise<void> {
    if (!this.currentSession) {
      throw new Error('No active session');
    }

    this.currentSession.msfSessions = this.currentSession.msfSessions.filter(
      (s) => s.sessionId !== sessionId
    );

    this.dirty = true;
    await this.save();
  }

  /**
   * Get all active MSF sessions
   */
  getMSFSessions(): MSFSession[] {
    return this.currentSession?.msfSessions || [];
  }

  /**
   * Update MSF session last checkin
   */
  async updateMSFCheckin(sessionId: number): Promise<void> {
    if (!this.currentSession) return;

    const session = this.currentSession.msfSessions.find(
      (s) => s.sessionId === sessionId
    );
    if (session) {
      session.lastCheckin = new Date().toISOString();
      this.dirty = true;
    }
  }

  // ==========================================================================
  // Sliver Beacon Management
  // ==========================================================================

  /**
   * Register a new Sliver beacon
   */
  async registerSliverBeacon(beacon: SliverBeacon): Promise<void> {
    if (!this.currentSession) {
      throw new Error('No active session');
    }

    const existing = this.currentSession.sliverBeacons.find(
      (b) => b.beaconId === beacon.beaconId
    );
    if (existing) {
      Object.assign(existing, beacon);
    } else {
      this.currentSession.sliverBeacons.push(beacon);
    }

    this.dirty = true;
    await this.save();
  }

  /**
   * Remove a Sliver beacon
   */
  async removeSliverBeacon(beaconId: string): Promise<void> {
    if (!this.currentSession) {
      throw new Error('No active session');
    }

    this.currentSession.sliverBeacons = this.currentSession.sliverBeacons.filter(
      (b) => b.beaconId !== beaconId
    );

    this.dirty = true;
    await this.save();
  }

  /**
   * Get all active Sliver beacons
   */
  getSliverBeacons(): SliverBeacon[] {
    return this.currentSession?.sliverBeacons || [];
  }

  // ==========================================================================
  // Key Findings Management
  // ==========================================================================

  /**
   * Add a key finding
   */
  async addFinding(finding: KeyFinding): Promise<void> {
    if (!this.currentSession) {
      throw new Error('No active session');
    }

    this.currentSession.keyFindings.push(finding);
    this.dirty = true;
    await this.save();
  }

  /**
   * Get all key findings
   */
  getFindings(): KeyFinding[] {
    return this.currentSession?.keyFindings || [];
  }

  /**
   * Get findings by type
   */
  getFindingsByType(type: KeyFinding['type']): KeyFinding[] {
    return this.getFindings().filter((f) => f.type === type);
  }

  /**
   * Get findings by severity
   */
  getFindingsBySeverity(severity: KeyFinding['severity']): KeyFinding[] {
    return this.getFindings().filter((f) => f.severity === severity);
  }

  // ==========================================================================
  // Context Window Management
  // ==========================================================================

  /**
   * Get context window
   */
  getContextWindow(): ContextWindow {
    return this.currentSession?.contextWindow || this.createEmptyContextWindow();
  }

  /**
   * Update context window
   */
  async updateContextWindow(window: ContextWindow): Promise<void> {
    if (!this.currentSession) {
      throw new Error('No active session');
    }
    this.currentSession.contextWindow = window;
    this.dirty = true;
  }

  // ==========================================================================
  // Session Lifecycle
  // ==========================================================================

  /**
   * List all sessions
   */
  async listSessions(): Promise<string[]> {
    return this.storage.list();
  }

  /**
   * Delete a session
   */
  async deleteSession(sessionId: string): Promise<void> {
    await this.storage.delete(sessionId);

    // If we deleted current session, clear it
    if (this.currentSession?.id === sessionId) {
      this.currentSession = null;
    }
  }

  /**
   * End the current session
   */
  async endSession(): Promise<void> {
    if (this.currentSession) {
      this.currentSession.phase = 'complete';
      await this.save();

      if (this.autoSaveInterval) {
        clearInterval(this.autoSaveInterval);
        this.autoSaveInterval = null;
      }

      this.currentSession = null;
    }
  }

  /**
   * Start auto-save interval
   */
  startAutoSave(intervalMs: number = 30000): void {
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
    }

    this.autoSaveInterval = setInterval(async () => {
      if (this.dirty) {
        await this.save();
      }
    }, intervalMs);
  }

  /**
   * Stop auto-save
   */
  stopAutoSave(): void {
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
      this.autoSaveInterval = null;
    }
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  private createEmptyContextWindow(): ContextWindow {
    return {
      maxTokens: 100000,
      currentTokens: 0,
      segments: [],
      lastCompaction: new Date().toISOString(),
      compressionRatio: 1.0,
    };
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a session manager with default storage
 */
export function createSessionManager(sessionDir?: string): SessionManager {
  const storage = new FileSessionStorage(sessionDir || DEFAULT_SESSION_DIR);
  return new SessionManager(storage);
}

/**
 * Get or create session for an engagement
 */
export async function getOrCreateSession(
  manager: SessionManager,
  engagementId: string,
  scope: EngagementScope
): Promise<StickySession> {
  // Try to initialize existing session
  const existing = await manager.initialize();
  if (existing && existing.engagementId === engagementId) {
    return existing;
  }

  // Create new session
  return manager.createSession(engagementId, scope);
}
