/**
 * Agent Opulence - Hooks Index
 *
 * Exports all plugin hooks.
 */

// Scope Firewall
export {
  handlePreToolUse as handleScopeCheck,
  handleExpansionResponse,
  setScopeManager,
  getScopeManager,
  default as scopeFirewallHook,
} from './scope-firewall';

// Policy Enforcer
export {
  handlePreToolUse as handlePolicyCheck,
  handleApprovalResponse,
  initializePolicyEngine,
  getPolicyEngine,
  updatePolicyScope,
  isToolAllowed,
  getToolPolicy,
  default as policyEnforcerHook,
} from './policy-enforcer';

// Output Processor
export {
  handlePostToolUse as handleOutputProcessing,
  setContextManager,
  getContextManager,
  getContextStats,
  getAgentContext,
  getArtifact,
  default as outputProcessorHook,
} from './output-processor';

// Session Hooks
export {
  handleSessionStart,
  handleSessionEnd,
  createEngagement,
  endEngagement,
  getSessionManager,
  getManifestUpdater,
  sessionRestoreHook,
  sessionSaveHook,
  default as sessionHooks,
} from './session-hooks';
