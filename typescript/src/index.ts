/**
 * The Secure AI SDK — data loss prevention for AI agents.
 *
 * The API is four HTTP calls and anybody can use it with fetch. This exists
 * because the shape that makes the product work is not "call an endpoint", it
 * is "put a check in front of every action", and the difference between those
 * two is whether somebody remembers to do it at the fourteenth call site.
 *
 * So the centre of this file is `guard`, which takes a function an agent
 * already calls and returns one that cannot run without a decision:
 *
 *     const post = guard("http.post", rawPost);
 *     await post({ url, body });   // blocked actions throw
 *
 * Everything else is the plumbing under it.
 *
 * ── No dependencies, on purpose ──
 *
 * This runs inside somebody's agent, next to their model client, their
 * framework and their vendor SDKs. Every dependency it adds is a version
 * conflict it can cause in a process that is already carrying too many, and a
 * security tool that is awkward to install is one that gets removed. It needs
 * fetch and nothing else: Node 18+, Bun, Deno, Cloudflare Workers, browsers.
 */

export type Decision = "allow" | "redact" | "approve" | "block";
export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";
export type Direction = "outbound" | "inbound";

export type Kind =
  | "secret" | "card" | "iban" | "ssn" | "govid"
  | "email" | "phone" | "address" | "postcode" | "name" | "host";

export interface Finding {
  kind: Kind;
  /** Where in the action it sat, e.g. "body.customer.email". */
  path: string;
  decision: Decision;
}

export interface Approval {
  id: string;
  createdAt: number;
  expiresAt: number;
  status: ApprovalStatus;
  agent: string | null;
  tool: string;
  keyId: string;
  findings: Finding[];
  decidedBy?: string;
  decidedAt?: number;
  note?: string;
}

export interface InspectResult<T = unknown> {
  decision: Decision;
  /** Set when the decision is "approve": the id to come back with once a
   *  person has decided. */
  approvalId?: string;
  /** When waiting stops being worth it. Milliseconds since epoch. */
  expiresAt?: number;
  /**
   * The action, ready to send. Absent when the decision is "block" — there is
   * deliberately nothing sendable in a refusal, so a caller cannot reach past
   * the decision by accident.
   */
  input?: T;
  /** {standIn: real}. Keep it: it is the only way to turn a reply back, and
   *  it is not stored on our side. */
  map: Record<string, string>;
  findings: Finding[];
  toolDenied: boolean;
  policySource: "account" | "default" | "unreadable";
  auditId: string;
}

export interface Rule {
  kind: Kind;
  decision: Decision;
  tools?: string[];
  direction?: Direction;
}

export interface Policy {
  version: 1;
  fallback: Decision;
  rules: Rule[];
  denyTools?: string[];
  allow?: string[];
}

/** An action the policy refused. Thrown by a guarded function rather than
 *  returned, because a refusal is not a result the caller should be able to
 *  ignore by not reading a field. */
export class ActionBlocked extends Error {
  readonly tool: string;
  readonly findings: Finding[];
  readonly toolDenied: boolean;
  readonly auditId: string;

  constructor(tool: string, result: InspectResult) {
    const what = result.toolDenied
      ? `the tool itself is not permitted`
      : result.findings
          .filter((f) => f.decision === "block")
          .map((f) => `${f.kind} at ${f.path || "the input"}`)
          .join(", ") || "policy";
    super(`Secure AI refused ${tool}: ${what}.`);
    this.name = "ActionBlocked";
    this.tool = tool;
    this.findings = result.findings;
    this.toolDenied = result.toolDenied;
    this.auditId = result.auditId;
  }
}

/**
 * A person refused this action, or nobody answered in time.
 *
 * Distinct from ActionBlocked because the answer to it is different: a policy
 * refusal is a rule to change, and this is a conversation to have. An agent
 * reporting "the policy forbids this" when in fact Dave clicked no would send
 * somebody to the wrong screen.
 */
export class ApprovalRefused extends Error {
  readonly tool: string;
  readonly approvalId: string;
  readonly status: ApprovalStatus;
  readonly note?: string;

  constructor(tool: string, approvalId: string, status: ApprovalStatus, note?: string) {
    super(
      status === "expired"
        ? `Secure AI held ${tool} for approval and nobody answered before it expired.`
        : `Secure AI held ${tool} for approval and it was refused${note ? `: ${note}` : "."}`,
    );
    this.name = "ApprovalRefused";
    this.tool = tool;
    this.approvalId = approvalId;
    this.status = status;
    if (note) this.note = note;
  }
}

/** The API answered, and said no. Separate from ActionBlocked: this is a
 *  problem with the call, not a decision about the action. */
export class SecureAIError extends Error {
  readonly status: number;
  readonly code: string | null;
  constructor(message: string, status: number, code: string | null) {
    super(message);
    this.name = "SecureAIError";
    this.status = status;
    this.code = code;
  }
}

export interface ClientOptions {
  apiKey: string;
  /** Overridable for staging and for tests. */
  baseUrl?: string;
  /** Names this agent in the audit trail, so its actions group together.
   *  Worth setting: a trail where everything is unnamed is a trail nobody
   *  can ask a question of. */
  agent?: string;
  /** Milliseconds before a call is abandoned. This sits in front of an
   *  agent's actions, so a hung check is a hung agent. */
  timeoutMs?: number;
  /** Injected for tests, and for runtimes with an unusual fetch. */
  fetch?: typeof globalThis.fetch;
  /**
   * What to do when Secure AI itself cannot be reached.
   *
   * "closed" — the default — throws, so an action is not taken while the
   * thing that governs it is down. That is the correct default for a security
   * control and it does mean an outage here stops agents.
   *
   * "open" lets the action through unchecked. It is offered because some
   * workloads genuinely prefer availability, and because a customer who wants
   * it will otherwise implement it themselves with a try/catch that also
   * swallows real refusals. Choosing it is a decision to record.
   */
  onUnreachable?: "closed" | "open";
}

const DEFAULT_BASE = "https://api.secureai.one";

export class SecureAI {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly agent?: string;
  private readonly timeoutMs: number;
  private readonly doFetch: typeof globalThis.fetch;
  private readonly onUnreachable: "closed" | "open";

  constructor(options: ClientOptions) {
    if (!options?.apiKey) throw new Error("SecureAI needs an apiKey.");
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE).replace(/\/+$/, "");
    this.agent = options.agent;
    this.timeoutMs = options.timeoutMs ?? 5_000;
    this.doFetch = options.fetch ?? globalThis.fetch;
    this.onUnreachable = options.onUnreachable ?? "closed";
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res: Response;
    try {
      res = await this.doFetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    const text = await res.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      // Falls through to the status-based error below. A non-JSON body from
      // this API means something in front of it answered, not the API.
    }

    if (!res.ok) {
      const err = (parsed as { error?: { message?: string; code?: string | null } } | null)?.error;
      throw new SecureAIError(
        err?.message ?? `Secure AI returned ${res.status}.`,
        res.status,
        err?.code ?? null,
      );
    }
    return parsed as T;
  }

  /** Judge an action without taking it. */
  async inspect<T = unknown>(action: {
    tool: string;
    input: T;
    direction?: Direction;
    agent?: string;
    /** Set when coming back after a person has decided. */
    approvalId?: string;
  }): Promise<InspectResult<T>> {
    return this.request<InspectResult<T>>("POST", "/v1/inspect", {
      tool: action.tool,
      input: action.input,
      direction: action.direction ?? "outbound",
      agent: action.agent ?? this.agent,
      ...(action.approvalId ? { approvalId: action.approvalId } : {}),
    });
  }

  /** One held action. */
  async approval(id: string): Promise<Approval> {
    const body = await this.request<{ approval: Approval }>("GET", `/v1/approvals/${encodeURIComponent(id)}`);
    return body.approval;
  }

  /** Everything waiting, for a reviewer's screen. */
  async approvals(opts?: { status?: ApprovalStatus; limit?: number }): Promise<Approval[]> {
    const q = new URLSearchParams();
    if (opts?.status) q.set("status", opts.status);
    if (opts?.limit) q.set("limit", String(opts.limit));
    const qs = q.toString();
    const body = await this.request<{ approvals: Approval[] }>("GET", `/v1/approvals${qs ? `?${qs}` : ""}`);
    return body.approvals;
  }

  /**
   * Wait for a person to decide.
   *
   * Polling, because it is the only mechanism that works in every runtime an
   * agent might be in — a held connection dies to platform timeouts, and a
   * callback needs the agent to be addressable, which a script on somebody's
   * laptop is not.
   *
   * Stops at the approval's own expiry rather than running forever: the
   * server will refuse it after that anyway, and a loop that outlives the
   * thing it is waiting for is a hung agent.
   */
  async waitForApproval(
    id: string,
    opts?: { pollMs?: number; signal?: AbortSignal },
  ): Promise<Approval> {
    const pollMs = Math.max(opts?.pollMs ?? 2_000, 250);
    for (;;) {
      const approval = await this.approval(id);
      if (approval.status !== "pending") return approval;
      if (Date.now() >= approval.expiresAt) return { ...approval, status: "expired" };
      if (opts?.signal?.aborted) throw new Error("Stopped waiting for approval.");
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }

  /** The rules currently in force. */
  async getPolicy(): Promise<{ policy: Policy; source: string }> {
    return this.request("GET", "/v1/policy");
  }

  /** Replace them. */
  async setPolicy(policy: Policy | Omit<Policy, "version">): Promise<{ policy: Policy }> {
    return this.request("PUT", "/v1/policy", { policy });
  }

  /** Stop flagging a value — a shared mailbox, your own domain. Applies to
   *  every agent on the account from the next action onwards. */
  async allowValue(value: string): Promise<{ policy: Policy; added: string }> {
    return this.request("POST", "/v1/policy/allow", { value });
  }

  /** What agents on this account have been doing. Kinds and locations only;
   *  no values are stored. */
  async audit(opts?: { limit?: number; cursor?: string }): Promise<{
    events: Array<{
      id: string; ts: number; keyId: string; agent: string | null;
      tool: string; direction: Direction; decision: Decision;
      toolDenied: boolean; findings: Finding[];
    }>;
    cursor: string | null;
  }> {
    const q = new URLSearchParams();
    if (opts?.limit) q.set("limit", String(opts.limit));
    if (opts?.cursor) q.set("cursor", opts.cursor);
    const qs = q.toString();
    return this.request("GET", `/v1/audit${qs ? `?${qs}` : ""}`);
  }

  /** The counts, over a recent window. */
  async summary(opts?: { limit?: number }): Promise<{
    window: number; actions: number; blocked: number; redacted: number; allowed: number;
    byKind: Array<{ kind: Kind; count: number }>;
    byTool: Array<{ tool: string; count: number }>;
  }> {
    const qs = opts?.limit ? `?limit=${opts.limit}` : "";
    return this.request("GET", `/v1/audit/summary${qs}`);
  }

  /** Put real values back into a reply, using the map from an inspection. */
  async restore(text: string, map: Record<string, string>): Promise<string> {
    const out = await this.request<{ text: string }>("POST", "/v1/restore", { text, map });
    return out.text;
  }

  /**
   * The point of the whole library: a function that cannot run unchecked.
   *
   * Wraps one tool. The returned function inspects, then calls the original
   * with the *rewritten* arguments — so an agent that never looks at a
   * decision still cannot send a real card number — and throws ActionBlocked
   * when the policy refuses.
   *
   * The original is called with the redacted input rather than the caller's,
   * and that is the whole mechanism. Returning a decision for the caller to
   * check would make protection opt-in at every site, which is the thing this
   * exists to stop.
   */
  guard<A, R>(
    tool: string,
    fn: (input: A) => Promise<R> | R,
    opts?: {
      direction?: Direction;
      agent?: string;
      /** Default true. False raises ApprovalRefused straight away instead. */
      waitForApproval?: boolean;
      pollMs?: number;
    },
  ): (input: A) => Promise<R> {
    return async (input: A): Promise<R> => {
      let verdict: InspectResult<A>;
      try {
        verdict = await this.inspect<A>({
          tool,
          input,
          direction: opts?.direction,
          agent: opts?.agent,
        });
      } catch (err) {
        // A refusal by the API — no key, no subscription, over quota — is a
        // real answer and must not be treated as an outage.
        if (err instanceof SecureAIError) throw err;
        if (this.onUnreachable === "open") return await fn(input);
        throw err;
      }

      if (verdict.decision === "block") throw new ActionBlocked(tool, verdict);

      /*
       * Held for a person.
       *
       * Waits by default, because the alternative — returning something the
       * caller has to notice and handle — puts the agent author in charge of
       * whether approval is enforced, which is the same mistake as returning
       * a verdict instead of calling through. Set waitForApproval: false to
       * get an ApprovalRefused immediately and handle it yourself.
       */
      if (verdict.decision === "approve") {
        const id = verdict.approvalId ?? "";
        if (!id) throw new ActionBlocked(tool, verdict);
        if (opts?.waitForApproval === false) {
          throw new ApprovalRefused(tool, id, "pending");
        }
        const decided = await this.waitForApproval(id, { pollMs: opts?.pollMs });
        if (decided.status !== "approved") {
          throw new ApprovalRefused(tool, id, decided.status, decided.note);
        }
        // Back with the id. The server re-checks the shape of what is being
        // sent, so a yes cannot be spent on a different action.
        const after = await this.inspect<A>({
          tool, input, direction: opts?.direction, agent: opts?.agent, approvalId: id,
        });
        if (after.decision === "block") throw new ActionBlocked(tool, after);
        return await fn((after.input ?? input) as A);
      }

      // input is present whenever the decision is not block; the fallback is
      // belt and braces against a future field being dropped.
      return await fn((verdict.input ?? input) as A);
    };
  }

  /**
   * A fetch that goes through the gateway.
   *
   * The other integration, for code that cannot be wrapped: hand this to
   * anything that takes a fetch — an SDK, a framework's HTTP client — and
   * every request it makes is inspected on the way out. No call sites change
   * at all, which is the difference between an afternoon and a sprint.
   *
   *     const openai = new OpenAI({ fetch: sai.fetch({ forwardAuth: key }) });
   *
   * A blocked request throws ActionBlocked rather than returning the 403, so
   * it fails the same way a guarded function does. A caller who would rather
   * see the response sets `throwOnBlock: false`.
   */
  fetch(opts?: {
    /** The credential for the destination, sent as its Authorization. Ours
     *  never travels — see forwardHeaders in the Worker. */
    forwardAuth?: string;
    agent?: string;
    throwOnBlock?: boolean;
  }): typeof globalThis.fetch {
    const throwOnBlock = opts?.throwOnBlock ?? true;
    return (async (input: string | URL | Request, init: RequestInit = {}) => {
      const target = typeof input === "string" || input instanceof URL
        ? String(input)
        : input.url;

      const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
      headers.set("Authorization", `Bearer ${this.apiKey}`);
      headers.set("X-Secure-AI-Target", target);
      if (opts?.forwardAuth) headers.set("X-Secure-AI-Forward-Authorization", opts.forwardAuth);
      const named = opts?.agent ?? this.agent;
      if (named) headers.set("X-Secure-AI-Agent", named);

      const res = await this.doFetch(`${this.baseUrl}/v1/gateway`, {
        ...init,
        method: init.method ?? (input instanceof Request ? input.method : "GET"),
        headers,
      });

      if (throwOnBlock && res.status === 403) {
        const body = await res.clone().json().catch(() => null) as
          | { error?: { code?: string; message?: string } }
          | null;
        if (body?.error?.code === "blocked_by_policy") {
          throw new ActionBlocked(target, {
            decision: "block", map: {}, findings: [], toolDenied: false,
            policySource: "account",
            auditId: res.headers.get("X-Secure-AI-Audit-Id") ?? "",
          });
        }
      }
      return res;
    }) as typeof globalThis.fetch;
  }
}

/** For callers who prefer a function to a class. */
export function createClient(options: ClientOptions): SecureAI {
  return new SecureAI(options);
}
