# QPassport

QPassport is a live production post quantum electronic travel document tool for issuing authorities and border control on the Quantova network. It proves the issue, endorsement, border inspection, renewal and revocation of a travel document, and it lets any third party confirm that history without trusting the party that created it.

QPassport proves records without disclosing them. Names, document numbers and travel history stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no personal detail is ever published. A holder is named only by a chain address.

## What it records

Each record is a signed envelope of one of five types.

1. issue, an authority states the document type, number, holder, issuing state and expiry of a travel document.
2. endorse, an authority adds an endorsement to the document.
3. inspect, a border inspector records an entry, exit or transit at a named post.
4. renew, the issuer extends the expiry of the document.
5. revoke, the issuer revokes the document and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of a document forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qpassport
```

## Use

```js
const qpassport = require('@quantovainc/qpassport');

const authority = qpassport.generateKey();
const holder = qpassport.generateKey();
const document = qpassport.issue({
  key: authority,
  docType: 'passport',
  docNo: 'P 1234567',
  subject: qpassport.keyId(holder),
  issuingState: 'GBR',
  validUntil: '2036-01-01T00:00:00.000Z',
  issuerLabel: 'Passport Office',
});

const anchored = await qpassport.anchor(document, { seed, index: 0, network: 'testnet' });
const result = await qpassport.verify(anchored[0], { type: 'issue', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural person. The holder and the authority are chain addresses, and linking an address to a person is a separate attestation held off the chain.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
