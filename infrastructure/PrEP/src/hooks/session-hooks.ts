/**
 * Agent Opulence - Session Lifecycle Hooks
 *
 * Handles session restoration and persistence.
 * Manages sticky sessions across Claude Code restarts.
 */

import {
  SessionManager,
  ScopeManager,
  ContextManager,
  ManifestUpdater,
  PolicyEngine,
  createSessionManager,
  createContextManager,
  createManifestUpdater,
  loadPolicy,
  StickySession,
  EngagementScope,
} from '../lib';
import { setScopeManager } from './scope-firewall';
import { initializePolicyEngine, updatePolicyScope } from './policy-enforcer';
import { setContextManager } from './output-processor';
import * as path from 'path';

// Configuration paths
const CONFIG = {
  sessionDir: '.opulence/sessions',
  manifestDir: '.opulence/manifest',
  policyPath: './policy.json',
  contextStatePath: '.opulence/context-state.json',
};

// Global instances
let sessionManager: SessionManager | null = null;
let manifestUpdater: ManifestUpdater | null = null;

/**
 * Get session manager
 */
export function getSessionManager(): SessionManager | null {
  return sessionManager;
}

/**
 * Get manifest updater
 */
export function getManifestUpdater(): ManifestUpdater | null {
  return manifestUpdater;
}

/**
 * Initialize all plugin components
 */
async function initializeComponents(session: StickySession): Promise<void> {
  // Initialize scope manager
  const scopeManager = new ScopeManager(session.scope);
  setScopeManager(scopeManager);

  // Initialize policy engine with scope
  await initializePolicyEngine(CONFIG.policyPath);
  updatePolicyScope();

  // Initialize context manager
  const contextManager = createContextManager();
  contextManager.addScope(session.scope);

  // Restore findings to context
  for (const finding of session.keyFindings) {
    contextManager.addFinding(finding);
  }

  setContextManager(contextManager);

  // Initialize manifest updater
  if (sessionManager) {
    manifestUpdater = await createManifestUpdater(CONFIG.manifestDir, sessionManager);
  }
}

/**
 * SessionStart hook - restores session state
 */
export async function handleSessionStart(): Promise<{
  restored: boolean;
  session?: StickySession;
  message: string;
}> {
  try {
    // Create session manager
    sessionManager = createSessionManager(CONFIG.sessionDir);

    // Try to restore existing session
    const session = await sessionManager.initialize();

    if (session) {
      // Initialize components with restored session
      await initializeComponents(session);

      // Start auto-save
      sessionManager.startAutoSave(30000);

      return {
        restored: true,
        session,
        message: `Restored engagement session: ${session.engagementId} (Phase: ${session.phase})`,
      };
    }

    return {
      restored: false,
      message: 'No existing session found. Use /opulence-init to start a new engagement.',
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      restored: false,
      message: `Session restoration failed: ${errorMessage}`,
    };
  }
}

/**
 * SessionEnd hook - persists session state
 */
export async function handleSessionEnd(): Promise<{
  saved: boolean;
  message: string;
}> {
  try {
    if (!sessionManager) {
      return {
        saved: false,
        message: 'No active session to save',
      };
    }

    // Stop auto-save
    sessionManager.stopAutoSave();

    // Final save
    await sessionManager.save();

    // Save manifest
    if (manifestUpdater) {
      await manifestUpdater.forceSave();
    }

    return {
      saved: true,
      message: 'Session state saved successfully',
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      saved: false,
      message: `Session save failed: ${errorMessage}`,
    };
  }
}

/**
 * Create new engagement session
 */
export async function createEngagement(
  name: string,
  scope: EngagementScope,
  type: string = 'generic'
): Promise<StickySession> {
  if (!sessionManager) {
    sessionManager = createSessionManager(CONFIG.sessionDir);
  }

  // Create new session
  const session = await sessionManager.createSession(name, scope);

  // Initialize components
  await initializeComponents(session);

  // Start auto-save
  sessionManager.startAutoSave(30000);

  return session;
}

/**
 * End current engagement
 */
export async function endEngagement(): Promise<void> {
  if (sessionManager) {
    await sessionManager.endSession();
    sessionManager.stopAutoSave();
  }

  sessionManager = null;
  manifestUpdater = null;
}

/**
 * Export hooks for Claude Code integration
 */
export const sessionRestoreHook = {
  name: 'session-restore',
  events: ['SessionStart'],
  handler: handleSessionStart,
};

export const sessionSaveHook = {
  name: 'session-save',
  events: ['SessionEnd'],
  handler: handleSessionEnd,
};

export default {
  sessionRestore: sessionRestoreHook,
  sessionSave: sessionSaveHook,
};
