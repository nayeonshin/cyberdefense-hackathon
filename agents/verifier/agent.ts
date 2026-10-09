import { llmAgent } from '@guildai/agents-sdk';
import { systemPrompt as reviewPrompt } from './prompt.js';
import { workflowPrompt } from './workflow-prompt.js';

type Tools = NonNullable<Parameters<typeof llmAgent>[0]['tools']>;

export interface VerifierBindings {
  scan: string;
  checkFeeds: string;
  readCapture: string;
  writeEvent: string;
}

/**
 * Wire only tools discovered with `guild integration operation list`.
 * No direct HTTP: Guild's sandbox routes requests through integration tools.
 * The CLI scaffold is present; real integrations are still required.
 */
export function createVerifier(tools: Tools, bindings: VerifierBindings) {
  const entries = Object.entries(bindings);
  if (new Set(entries.map(([, name]) => name)).size !== entries.length) {
    throw new Error('Verifier requires four distinct integration operations');
  }
  const selected = Object.fromEntries(entries.map(([role, name]) => {
    const tool = tools[name];
    if (!tool) throw new Error(`Missing integration operation for ${role}: ${name}`);
    return [name, tool];
  })) as Tools;
  let systemPrompt = workflowPrompt;
  for (const [role, name] of entries) {
    systemPrompt = systemPrompt.replaceAll(`{{${role}}}`, name);
  }
  return llmAgent({
    description: 'Verifier: scan pending URLs and explain suspicious code with cited evidence',
    tools: selected,
    systemPrompt,
    mode: 'one-shot',
    useWorkspaceAgents: false,
  });
}

// Buildable second-opinion fallback until the four integration operations exist.
// Receives the scanner result and captured sources as JSON text; makes no calls.
export default llmAgent({
  description: 'Reviews supplied Semgrep findings and captured scripts; no external tools configured',
  tools: {},
  systemPrompt: reviewPrompt,
  mode: 'one-shot',
  useWorkspaceAgents: false,
});
