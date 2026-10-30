// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

const OPTS = { network: 'testnet', requireAnchor: false, strict: false };

function issue() {
  const key = Q.generateKey();
  const holder = Q.generateKey();
  return { key, env: Q.issue({ key, docType: 'passport', docNo: 'P 1234567', subject: Q.keyId(holder), issuingState: 'GBR', validUntil: '2036-01-01T00:00:00.000Z' }) };
}

test('replay as another record type is refused', async () => {
  const { env } = issue();
  const forged = JSON.parse(JSON.stringify(env));
  forged.type = 'endorse';
  const r = await Q.verify(forged, Object.assign({ type: 'endorse' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('replay onto another document id is refused', async () => {
  const { env } = issue();
  const forged = JSON.parse(JSON.stringify(env));
  forged.statement.passportId = 'f'.repeat(32);
  const r = await Q.verify(forged, Object.assign({ type: 'issue' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('every signed field is bound, a change to any of them breaks the signature', async () => {
  const { env } = issue();
  const mutations = [
    (s) => { s.docType = 'diplomatic'; },
    (s) => { s.docNo = 'P 9999999'; },
    (s) => { s.subjectKeyId = (s.subjectKeyId[0] === '0' ? '1' : '0') + s.subjectKeyId.slice(1); },
    (s) => { s.issuingState = 'FRA'; },
    (s) => { s.validUntil = '2099-01-01T00:00:00.000Z'; },
    (s) => { s.issuedAt = '2000-01-01T00:00:00.000Z'; },
    (s) => { s.note = 'added'; },
  ];
  for (const mutate of mutations) {
    const forged = JSON.parse(JSON.stringify(env));
    mutate(forged.statement);
    const r = await Q.verify(forged, Object.assign({ type: 'issue' }, OPTS));
    assert.strictEqual(r.status, 'invalid', JSON.stringify(forged.statement));
  }
});

test('a signature from a key other than the named signer does not verify', async () => {
  const a = issue();
  const b = issue();
  const forged = JSON.parse(JSON.stringify(a.env));
  forged.signer = b.env.signer;
  const r = await Q.verify(forged, Object.assign({ type: 'issue' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('a non canonical base64 public key or signature is rejected at parse', async () => {
  const { env } = issue();
  for (const field of ['publicKey']) {
    const forged = JSON.parse(JSON.stringify(env));
    forged.signer[field] = forged.signer[field].slice(0, -2) + '==';
    const r = await Q.verify(forged, Object.assign({ type: 'issue' }, OPTS));
    assert.strictEqual(r.status, 'invalid');
  }
  const bad = JSON.parse(JSON.stringify(env));
  bad.signature = bad.signature.slice(0, -4) + 'AAAA';
  const r = await Q.verify(bad, Object.assign({ type: 'issue' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('an envelope with an unexpected field is refused', async () => {
  const { env } = issue();
  const forged = JSON.parse(JSON.stringify(env));
  forged.extra = 1;
  const r = await Q.verify(forged, Object.assign({ type: 'issue' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  const withStatementExtra = JSON.parse(JSON.stringify(env));
  withStatementExtra.statement.extra = 1;
  const r2 = await Q.verify(withStatementExtra, Object.assign({ type: 'issue' }, OPTS));
  assert.strictEqual(r2.status, 'invalid');
});

test('a statement carrying a prototype polluting key is refused', async () => {
  const { env } = issue();
  const forged = JSON.parse(JSON.stringify(env));
  forged.statement = JSON.parse('{"__proto__":{"polluted":true},"passportId":"' + env.statement.passportId + '"}');
  const r = await Q.verify(forged, Object.assign({ type: 'issue' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.strictEqual({}.polluted, undefined);
});

test('a signing key is never serialised by the SDK', () => {
  const key = Q.generateKey();
  assert.strictEqual(JSON.stringify({ key }), '{"key":"SecretKey [hidden]"}');
  assert.strictEqual(String(key), 'SecretKey [hidden]');
  assert.strictEqual(require('util').inspect(key), 'SecretKey [hidden]');
});

test('an anchor recorded under another record kind is not accepted', async () => {
  const { env } = issue();
  const anchored = JSON.parse(JSON.stringify(env));
  anchored.anchor = { kind: '1301', chain: { id: 'x', genesis: 'y' }, anchor: { time: 1, height: 1, tx: 't' }, proof: { index: 0 } };
  const r = await Q.verify(anchored, Object.assign({ type: 'issue', requireAnchor: true }, { network: 'testnet', strict: false }));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => /anchor/.test(c.name) && !c.ok));
});
