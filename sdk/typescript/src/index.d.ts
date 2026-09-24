/**
 * Type declarations for @uai/sdk.
 *
 * Hand-written, and committed rather than generated, for the same reason the
 * package has no build step: what is published is what is in the repository.
 * The cost is that these can drift from the implementation, so
 * `test/types.test.mjs` asserts that every runtime export has a declaration and
 * every declaration has a runtime export. That catches a missing or renamed
 * export; it does not catch a changed signature, which is the honest limit of
 * this approach and the reason the declarations stay small.
 */

export declare const VERSION: string;

// ── canonicalization ────────────────────────────────────────────────────────

export declare function canonicalize(value: unknown): Uint8Array;
export declare function canonicalString(value: unknown): string;
export declare function canonicalizeJSON(raw: string): Uint8Array;
/** The canonical form with the named top-level members removed: what a
 * signature over a self-signed object covers (10.4). */
export declare function canonicalizeWithout(
  value: Record<string, unknown>, ...members: string[]): Uint8Array;

// ── cryptography ────────────────────────────────────────────────────────────

export declare const SALT_LEN: 32;

export declare const Domain: Readonly<{
  ATTESTATION: 'UAI-v1:attestation';
  CREDENTIAL: 'UAI-v1:credential';
  DID_DOCUMENT: 'UAI-v1:did-document';
  REGISTRATION: 'UAI-v1:registration';
  CHALLENGE: 'UAI-v1:challenge';
  VOTE: 'UAI-v1:vote';
  DECISION: 'UAI-v1:decision';
  POLICY_BUNDLE: 'UAI-v1:policy-bundle';
  QUARANTINE: 'UAI-v1:quarantine';
  REVOCATION: 'UAI-v1:revocation';
  CHECKPOINT: 'UAI-v1:checkpoint';
  COMMITMENT: 'UAI-v1:commitment';
  AUDIT: 'UAI-v1:audit';
  CAPABILITY_REQUEST: 'UAI-v1:capability-request';
  SUSPICION: 'UAI-v1:suspicion';
  PASSPORT: 'UAI-v1:passport';
}>;

export type DomainName = (typeof Domain)[keyof typeof Domain];

export interface Signature {
  alg: string;
  kid: string;
  domain: string;
  value: string;
}

export interface JWK {
  kty?: string;
  crv?: string;
  x?: string;
  d?: string;
}

export declare class Signer {
  static readonly ALG: 'EdDSA';
  static readonly HTTP_ALG: 'ed25519';
  constructor(privateKey: unknown, kid: string);
  static fromJWK(jwk: JWK, kid: string): Signer;
  static fromFile(path: string, kid: string): Promise<Signer>;
  readonly kid: string;
  readonly did: string;
  publicJWK(): { kty: string; crv: string; x: string };
  signRaw(message: Uint8Array): Uint8Array;
  sign(domain: DomainName | string, payload: Uint8Array): Signature;
  signObject(domain: DomainName | string, value: unknown): Signature;
}

export declare function signingInput(domain: string, payload: Uint8Array): Uint8Array;
export declare function digest(domain: string, payload: Uint8Array): Uint8Array;
export declare function digestObject(domain: string, value: unknown): Uint8Array;
export declare function salt(): Uint8Array;
export declare function commit(saltBytes: Uint8Array, content: Uint8Array): Uint8Array;
export declare function commitObject(saltBytes: Uint8Array, value: unknown): Uint8Array;
export declare function verifyCommitment(
  commitment: Uint8Array, saltBytes: Uint8Array, content: Uint8Array): boolean;
export declare function formatDigest(raw: Uint8Array): string;
export declare function thumbprintInput(jwk: Record<string, unknown>): string;
/** The RFC 7638 thumbprint in the UAI wire form. It is the subject identifier
 * of a registration proof, so all implementations must agree on it exactly. */
export declare function jwkThumbprint(jwk: Record<string, unknown>): string;
export declare function b64url(raw: Uint8Array): string;
export declare function b64urlDecode(text: string): Uint8Array;
export declare function verify(
  publicKey: unknown, domain: string, payload: Uint8Array, signature: Signature): void;

// ── proof of possession ─────────────────────────────────────────────────────

export declare const DEFAULT_COMPONENTS: readonly string[];

export interface SignatureParams {
  components?: readonly string[];
  created?: number;
  expires?: number;
  keyId: string;
  alg?: string;
  nonce?: string;
  tag: string;
}

export interface SignedMessage {
  method: string;
  url: string;
  headers: Record<string, string>;
}

export declare function nonce(): string;
export declare function contentDigest(body: Uint8Array | string): string;
export declare function serializeParams(params: SignatureParams): string;
export declare function signatureBase(message: SignedMessage, params: SignatureParams): Uint8Array;
export declare function signRequest(signer: Signer, request: {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body: Uint8Array | string;
  domain: string;
  agentId: string;
  replayNonce?: string;
  created?: number;
}): Record<string, string>;

// ── errors ──────────────────────────────────────────────────────────────────

export declare class UAIError extends Error {}

export declare class Problem extends UAIError {
  constructor(status: number, document: Record<string, unknown>);
  readonly status: number;
  readonly document: Record<string, unknown>;
  /** The `UAI_*` code. Match on this, never on the message. */
  readonly code: string;
  readonly detail: string;
  readonly remediation: string;
  readonly decisionId: string;
  readonly policyVersion: string;
  readonly chainHead: { hash: string; sequence: number } | null;
}

export declare class PolicyRefused extends UAIError {
  constructor(decision: Decision);
  readonly decision: Decision;
}

export declare class NotAttested extends UAIError {
  constructor(message: string, cause?: unknown);
}

// ── the agent ───────────────────────────────────────────────────────────────

export interface Jurisdiction {
  origin: string;
  targets?: string[];
  basis?: string;
}

export interface ResolvedJurisdiction {
  origin: string;
  targets: string[];
  /** Derived from origin and targets, never declared by the caller. */
  cross_border: boolean;
  basis: string;
}

export interface Decision {
  decisionId: string;
  /** ALLOW, ALLOW_WITH_MONITORING, REQUIRE_HUMAN_APPROVAL, QUARANTINE or DENY. */
  effect: string;
  reason: string;
  policyVersion: string;
  bundleHash: string;
  rulesFired: string[];
  conditions: Record<string, unknown>;
  raw: Record<string, unknown>;
}

export interface Intent {
  capability: string;
  purpose: string;
  type?: string;
  resource?: string;
  riskClass?: string;
  jurisdiction?: Jurisdiction;
  /** Committed locally with a fresh salt. The value itself is never sent. */
  input?: unknown;
  runtimeIdentity?: string;
  /** Throw NotAttested when the work ran but could not be recorded. */
  strict?: boolean;
}

export interface ActionRecord<T = unknown> {
  decision: Decision;
  /** SUCCESS, FAILURE or ABORTED_BY_POLICY. */
  outcome: string;
  eventId: string;
  eventHash: string;
  sequence: number;
  /** LOGGED, UNLOGGED or LOG_UNAVAILABLE. UNLOGGED is not an error. */
  transparency: string;
  receipt: unknown;
  /** Keep these. UAI does not have them, so a discarded salt is a commitment
   * nobody can ever open. */
  inputSalt: Uint8Array | null;
  outputSalt: Uint8Array | null;
  /** Set when the action ran but was not recorded. */
  attestError: unknown;
  result?: T;
}

export declare class Transport {
  constructor(options: {
    endpoint: string;
    uaiId: string;
    signer: Signer;
    timeoutMs?: number;
    fetch?: typeof globalThis.fetch;
  });
  get(path: string): Promise<any>;
  post(path: string, domain: string, body: unknown): Promise<any>;
  postPublic(path: string, body: unknown): Promise<any>;
}

export declare class Agent {
  constructor(options: {
    endpoint: string;
    uaiId: string;
    signer: Signer;
    ownerDid?: string;
    timeoutMs?: number;
  });
  static fromEnv(env?: Record<string, string | undefined>): Promise<Agent>;
  readonly uaiId: string;
  readonly did: string;
  readonly ownerDid: string;
  readonly transport: Transport;
  readonly signer: Signer;
  act<T>(intent: Intent, work: () => T | Promise<T>): Promise<ActionRecord<T>>;
  evaluate(intent: Intent): Promise<Decision>;
  chainHead(): Promise<{ hash: string; sequence: number }>;
  verify(uaiId: string): Promise<Record<string, any>>;
  status(): Promise<Record<string, any>>;
  events(options?: { uaiId?: string; limit?: number }): Promise<Record<string, any>>;
  requestCapability(request: {
    capability: string;
    justification: string;
    purpose?: string;
  }): Promise<Record<string, any>>;
  checkPassport(check: {
    capability: string;
    targets: string[];
    subject?: string;
    riskClass?: string;
  }): Promise<Record<string, any>>;
  reportHarm(report: {
    subject: { agent_did: string; owner_did: string };
    /** severity is 0-4. There is deliberately no field for a finding. */
    harmCategories: { category: string; severity: number }[];
    confidence: number;
    relatedEvents?: string[];
    reporterType?: string;
    guardrail?: { rule?: string; policy_version?: string; bundle_hash?: string };
    evidenceCommitments?: string[];
    affectedJurisdictions?: string[];
  }): Promise<Record<string, any>>;
}

export declare function allows(decision: Decision): boolean;
export declare function jurisdiction(j: Jurisdiction): ResolvedJurisdiction;
