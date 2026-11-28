// Minimal types for the parts of @stafordtituss/amep (plain JavaScript) used here.
declare module '@stafordtituss/amep' {
  export type AmepObject = Record<string, unknown> & { id?: string; kind: string };
  export interface AmepResult {
    id: string;
    outcome: 'preserved' | 'violated' | 'unresolved';
    invariant: string;
    reason: string;
  }
  export class Key {
    static generate(kid: string, roles: string[]): Key;
    readonly kid: string;
    sign<T extends AmepObject>(obj: T, opts?: { v?: 1 | 2 }): T & { proof: Record<string, unknown> };
  }
  export function keyset(...keys: Key[]): Record<string, unknown>;
  export function verifyPacket(
    packet: Record<string, unknown>,
    keys: Record<string, unknown>,
  ): { results: AmepResult[]; verdict: AmepResult };
  export const VERSION: string;
  export const sdk: {
    claims(
      actions: string[],
      resources: string[],
      ceiling: string,
      exp: string | number,
      opts?: { nbf?: string | number; purpose?: string; depth?: number },
    ): Record<string, unknown>;
    mandate(id: string, principal: string, claims: Record<string, unknown>, opts?: { issuer?: string; subjectAgent?: string }): AmepObject;
    delegation(id: string, parent: string, claims: Record<string, unknown>, opts?: { delegate?: string }): AmepObject;
    interpretation(id: string, adapter: string, version: string, opts?: { source?: string }): AmepObject;
    invocation(
      id: string,
      authorityRef: string,
      interpretationRef: string,
      t: string | number,
      action: string,
      resource: string,
      effect: string,
      opts?: { actor?: string },
    ): AmepObject;
    effectBody(action: string, resource: string, effect: string, t: string | number): Record<string, unknown>;
    effect(id: string, invocationId: string, observedBy: string, assurance: string, executed: Record<string, unknown>): AmepObject;
    callStatement(id: string, invocationId: string, observedBy: string, disposition: string, effectCount: number, t: string | number): AmepObject;
    revocation(target: string, t: string | number, opts?: { id?: string }): AmepObject;
    enforcement(pep: string, failMode: string): Record<string, unknown>;
    decision(
      invocationId: string,
      outcome: string,
      mode: string,
      phase: string,
      opts?: { id?: string; enforcement?: Record<string, unknown> },
    ): AmepObject;
    packet(objects: AmepObject[], opts?: { pinnedAdapters?: Record<string, string>; amepVersion?: "0.2" | "0.3" }): Record<string, unknown>;
  };
}
