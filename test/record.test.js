// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function issueDocument(key, subject) {
  return Q.issue({ key, docType: 'passport', docNo: 'P 1234567', subject: Q.keyId(subject), issuingState: 'GBR', validUntil: '2036-01-01T00:00:00.000Z', issuerLabel: 'Passport Office' });
}

test('an issued document is a well formed signed record of the issuer', () => {
  const authority = freshKey();
  const holder = freshKey();
  const doc = issueDocument(authority, holder);
  assert.strictEqual(doc.format, 'qpassport/1');
  assert.strictEqual(doc.type, 'issue');
  assert.strictEqual(doc.algorithm, 'ML-DSA-65');
  assert.strictEqual(doc.signer.id, Q.keyId(authority));
  assert.strictEqual(doc.statement.issuerKeyId, Q.keyId(authority));
  assert.strictEqual(doc.statement.subjectKeyId, Q.keyId(holder));
  assert.match(doc.statement.passportId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(doc.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(doc.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the endorse, inspect and renew records chain to the same document', () => {
  const authority = freshKey();
  const holder = freshKey();
  const inspector = freshKey();
  const doc = issueDocument(authority, holder);
  const end = Q.endorse({ key: authority, passport: doc, endorsement: 'Residence permit class A' });
  const insp = Q.inspect({ key: inspector, record: doc, direction: 'entry', post: 'LHR Terminal 5' });
  const ren = Q.renew({ key: authority, record: insp, validUntil: '2040-01-01T00:00:00.000Z' });
  assert.strictEqual(end.statement.passportId, doc.statement.passportId);
  assert.strictEqual(end.statement.issueRef, Q.recordRef(doc));
  assert.strictEqual(insp.statement.priorRef, Q.recordRef(doc));
  assert.strictEqual(ren.statement.priorRef, Q.recordRef(insp));
  assert.strictEqual(insp.statement.direction, 'entry');
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const holder = freshKey();
  const base = { key, docType: 'passport', docNo: 'P1', subject: Q.keyId(holder), issuingState: 'GBR', validUntil: '2036-01-01T00:00:00.000Z' };
  assert.throws(() => Q.issue(Object.assign({}, base, { docType: 'library' })), /docType must be one of/);
  assert.throws(() => Q.issue(Object.assign({}, base, { docNo: '' })), /docNo is 1 to/);
  assert.throws(() => Q.issue(Object.assign({}, base, { subject: 'nothex' })), /subject is a/);
  assert.throws(() => Q.issue(Object.assign({}, base, { unknownField: 1 })), /is not an option of issue/);
  const doc = issueDocument(key, holder);
  assert.throws(() => Q.inspect({ key, record: doc, direction: 'sideways', post: 'LHR' }), /direction must be one of/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  const holder = freshKey();
  assert.throws(() => issueDocument(new Uint8Array(16), holder), /32 byte Uint8Array seed/);
  assert.throws(() => issueDocument(new Uint8Array(32), holder), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const authority = freshKey();
  const holder = freshKey();
  const doc = issueDocument(authority, holder);
  const ok = await Q.verify(doc, { type: 'issue', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'issue');
  assert.strictEqual(ok.passportId, doc.statement.passportId);
  const wrongType = await Q.verify(doc, { type: 'inspect', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(doc, { type: 'issue', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const authority = freshKey();
  const holder = freshKey();
  const doc = issueDocument(authority, holder);
  const forged = JSON.parse(JSON.stringify(doc));
  forged.statement.issuingState = 'FRA';
  const r = await Q.verify(forged, { type: 'issue', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds an inspection to the document it refers to', async () => {
  const authority = freshKey();
  const holder = freshKey();
  const inspector = freshKey();
  const doc = issueDocument(authority, holder);
  const insp = Q.inspect({ key: inspector, record: doc, direction: 'entry', post: 'LHR Terminal 5' });
  const good = await Q.verify(insp, { type: 'inspect', network: 'testnet', requireAnchor: false, strict: false, prior: doc });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherDoc = issueDocument(authority, holder);
  const bad = await Q.verify(insp, { type: 'inspect', network: 'testnet', requireAnchor: false, strict: false, prior: otherDoc });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'P 1234567');
  const b = Q.subjectRef(secret, 'P 1234567');
  const c = Q.subjectRef(secret, 'P 1234568');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the travel document line', () => {
  assert.strictEqual(Q.KIND, 1502);
  assert.strictEqual(Q.FORMAT, 'qpassport/1');
  assert.deepStrictEqual([...Q.TYPES], ['issue', 'endorse', 'inspect', 'renew', 'revoke']);
  assert.deepStrictEqual([...Q.DOCTYPES], ['passport', 'emergency', 'diplomatic', 'service', 'refugee']);
  assert.deepStrictEqual([...Q.DIRECTIONS], ['entry', 'exit', 'transit']);
});
