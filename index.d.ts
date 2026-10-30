// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type DocType = 'passport' | 'emergency' | 'diplomatic' | 'service' | 'refugee';
export type Direction = 'entry' | 'exit' | 'transit';
export type RecordType = 'issue' | 'endorse' | 'inspect' | 'renew' | 'revoke';

export interface KeyDescription {
  format: 'qpassport-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qpassport/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface IssueOptions {
  key: Uint8Array;
  docType: DocType;
  docNo: string;
  subject: Party;
  issuingState: string;
  validUntil: string;
  issuerLabel?: string;
  issuedAt?: string;
  note?: string;
}

export interface EndorseOptions {
  key: Uint8Array;
  passport: Envelope;
  endorsement: string;
  authorityLabel?: string;
  endorsedAt?: string;
  note?: string;
}

export interface InspectOptions {
  key: Uint8Array;
  record: Envelope;
  direction: Direction;
  post: string;
  inspectorLabel?: string;
  inspectedAt?: string;
  note?: string;
}

export interface RenewOptions {
  key: Uint8Array;
  record: Envelope;
  validUntil: string;
  issuerLabel?: string;
  renewedAt?: string;
  note?: string;
}

export interface RevokeOptions {
  key: Uint8Array;
  record: Envelope;
  reason: string;
  issuerLabel?: string;
  revokedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  passportId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  passportId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, reference: string): string;
export function issue(options: IssueOptions): Envelope;
export function endorse(options: EndorseOptions): Envelope;
export function inspect(options: InspectOptions): Envelope;
export function renew(options: RenewOptions): Envelope;
export function revoke(options: RevokeOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qpassport/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1502;
export const TYPES: readonly RecordType[];
export const DOCTYPES: readonly DocType[];
export const DIRECTIONS: readonly Direction[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
