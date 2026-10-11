// The privacy layer for this server. Three calls, used by every tool:
//
//   hide(value)            before a result goes to the model
//   reveal(args)           before the model's request reaches your systems
//   check(tool, args)      before anything acts: your account's rules decide
//
// The stand-ins are kept here, in memory, for as long as the server runs.
// They are never sent anywhere: Secure AI keeps no copy of them either.
import { SecureAI } from "@secure-ai/guard";

const apiKey = process.env.SECURE_AI_KEY;
if (!apiKey) {
  console.error("Set SECURE_AI_KEY (secureai.one -> Settings -> Developer).");
  process.exit(1);
}

export const sai = new SecureAI({ apiKey, agent: process.env.npm_package_name ?? "secure-mcp" });

/** stand-in -> real value, for this run of the server. */
const vault = new Map<string, string>();

/** Swap private details for stand-ins before the model sees them. */
export async function hide<T>(tool: string, value: T): Promise<T> {
  const result = await sai.inspect({ tool, input: value, direction: "inbound" });
  for (const [standIn, real] of Object.entries(result.map ?? {})) vault.set(standIn, real);
  if (result.decision === "block" || result.input === undefined) {
    throw new Error(`Secure AI kept this result from the model (${tool}).`);
  }
  return result.input as T;
}

/** Put the real values back into what the model asked for. Local only. */
export function reveal<T>(value: T): T {
  let text = JSON.stringify(value);
  // Longest first, so "Ana Ruiz" is not half-replaced by "Ana".
  for (const [standIn, real] of [...vault].sort((a, b) => b[0].length - a[0].length)) {
    text = text.split(JSON.stringify(standIn).slice(1, -1)).join(JSON.stringify(real).slice(1, -1));
  }
  return JSON.parse(text) as T;
}

/** Ask your account's rules whether an action may happen. Waits for a
 *  person when a rule says so; throws when the answer is no. */
export async function check(tool: string, args: unknown): Promise<void> {
  const result = await sai.inspect({ tool, input: args, direction: "outbound" });
  if (result.decision === "allow" || result.decision === "redact") return;
  if (result.decision === "approve" && result.approvalId) {
    const answer = await sai.waitForApproval(result.approvalId);
    if (answer.status === "approved") return;
    throw new Error(`Not approved (${answer.status}): ${tool} did not run.`);
  }
  throw new Error(`Secure AI blocked ${tool}: your rules do not allow it.`);
}
