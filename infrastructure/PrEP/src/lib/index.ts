/**
 * Agent Opulence - PrEP Library
 *
 * Main export file for all plugin components.
 */

// Types
export * from '../types';

// Scope Management
export {
  ScopeManager,
  isIPInCIDR,
  isValidIPv4,
  matchDomain,
  extractDomain,
  createEmptyScope,
  createHTBScope,
  createHTBScopeManager,
} from './scope-manager';

// Policy Engine
export {
  PolicyEngine,
  loadPolicy,
  createDefaultPolicy,
  createPolicyEngine,
} from './security';

// Session Management
export {
  SessionManager,
  createSessionManager,
  getOrCreateSession,
} from './session-manager';

// Manifest Management
export {
  ManifestUpdater,
  loadManifest,
  saveManifest,
  createEmptyManifest,
  createManifestUpdater,
} from './manifest-updater';

// Context Management
export {
  ContextManager,
  createContextManager,
  createHTBContextManager,
  type MaskedToolOutput,
  type ContextSnapshot,
  type MaskingConfig,
} from './context-manager';

// Window Management
export {
  WindowManager,
  createWindowManager,
  restoreWindowManager,
  type WindowConfig,
} from './window-manager';

// Extractors
export {
  extractFindings,
  extractFromNmap,
  extractFromNuclei,
  extractFromHttpx,
  extractFromSubfinder,
  extractFromMSF,
  extractFromGeneric,
  type ExtractionResult,
} from './extractors';
