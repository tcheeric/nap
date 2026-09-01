import express from 'express';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { getPublicKey, nip19 } from 'nostr-tools';
import { hexToBytes } from '@imani/nap-core';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import {
  InMemoryChallengeStore,
  InMemorySessionStore,
  type NapServerOptions,
} from '@imani/nap-server';
import {
  createNapExpressRouter,
  createRequestDerivedBaseUrlResolver,
} from '@imani/nap-adapter-express';
import { createIssuerAllowlist, createMintAllowlist } from '../src/allowlist.js';
import { createMintAvailabilityPolicy } from '../src/availability.js';
import { createVoucherAclResolver } from '../src/resolver.js';
import type { MintClient } from '../src/mintClient.js';
import { parseVoucherSecret, voucherCanonicalBytes } from '../src/secret.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes as hexToBytesNoble } from '@noble/hashes/utils.js';

/**
 * The ordering property that the resolver's own tests cannot establish.
 *
 * §6 requires the whole procedure to run *after* RFC steps 1-12. If it did not,
 * `/auth/complete` would be a free oracle: an unauthenticated caller submits a
 * proof they do not own, and the server's outbound NUT-07 check tells them
 * whether it is spent. That is a privacy break against the mint's users, and it
 * makes this endpoint a laundering service for probing arbitrary proofs.
 *
 * Where the check runs is a fact about `server.ts`, not about the resolver, so
 * asserting it means driving the real endpoint with a real adapter and watching
 * whether the mint client is touched. A unit test of the resolver would pass
 * whether or not the ordering held.
 */

const PK = '1111111111111111111111111111111111111111111111111111111111111111';
const NPUB = nip19.npubEncode(getPublicKey(hexToBytes(PK)));
const NOW = 1_710_000_000;
const MINT = 'https://mint.example.com';
const ISSUER_PRIVATE = hexToBytesNoble('11'.repeat(32));
const ISSUER_PUBKEY = bytesToHex(schnorr.getPublicKey(ISSUER_PRIVATE));

/** A voucher genuinely signed by the allowlisted issuer and locked to `lockedTo`. */
function signedSecret(lockedTo: string): string {
  const body = { nonce: 'n', data: `02${lockedTo}`, tags: [['issuer', 'imani']] };
  const unsigned = parseVoucherSecret(JSON.stringify(['P2PK_VOUCHER', body]))!;
  const sig = bytesToHex(schnorr.sign(sha256(voucherCanonicalBytes(unsigned)), ISSUER_PRIVATE));
  return JSON.stringify([
    'P2PK_VOUCHER',
    { ...body, tags: [...body.tags, ['issuer_pubkey', ISSUER_PUBKEY], ['issuer_sig', sig]] },
  ]);
}

function build() {
  const getKey = vi.fn(async () => '02'.padEnd(66, 'b'));
  const checkState = vi.fn(async () => 'UNSPENT' as const);

  const options: NapServerOptions = {
    challengeStore: new InMemoryChallengeStore(),
    sessionStore: new InMemorySessionStore(),
    aclResolver: createVoucherAclResolver({
      mintAllowlist: createMintAllowlist([MINT]),
      issuerAllowlist: createIssuerAllowlist(
        [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
        createMintAllowlist([MINT])
      ),
      mintClient: { getKey, checkState, clearCache: () => {} } as MintClient,
      availability: createMintAvailabilityPolicy(),
      grant: () => ({ roles: ['voucher-holder'], permissions: ['voucher:view'] }),
    }),
    minAuthResponseMillis: 0,
    clock: { nowUnix: () => NOW },
  };

  const app = express();
  app.set('trust proxy', true);
  app.use(
    '/auth',
    createNapExpressRouter({
      server: options,
      getExternalBaseUrl: createRequestDerivedBaseUrlResolver(['api.example.com']),
    })
  );

  return { app, getKey, checkState };
}

const send = (app: express.Express, path: string) =>
  request(app).post(path).set('host', 'api.example.com').set('x-forwarded-proto', 'https');

/**
 * A credential that reaches the mint the moment the server lets it.
 *
 * Deliberately *valid*: allowlisted mint, allowlisted issuer, real issuer
 * signature, and locked to the key that signs the login. Every local check
 * passes, so the only thing standing between this request and an outbound
 * NUT-07 state check is the ordering under test.
 *
 * An earlier version of this file used a voucher locked to somebody else. That
 * made the tests vacuous -- step (d) rejected it before the mint regardless of
 * ordering, so they passed even when the ACL resolution was hoisted above the
 * NIP-98 check. A prober would use a voucher that passes, which is the point:
 * they are probing the state of a proof, not trying to log in.
 */
const CREDENTIAL = {
  mint_url: MINT,
  keyset_id: '00882760bfa2eb41',
  secret: signedSecret(getPublicKey(hexToBytes(PK))),
  signature: '02'.padEnd(66, 'a'),
  amount: 8,
  dleq: { e: 'e'.repeat(64), s: 's'.padEnd(64, '0'), r: 'r'.padEnd(64, '0') },
};

describe('/auth/complete is not a mint oracle', () => {
  it('never contacts the mint for a completion with no NIP-98 authorization', async () => {
    const { app, getKey, checkState } = build();
    const init = await send(app, '/auth/init').send({ npub: NPUB });

    const response = await send(app, '/auth/complete').send({
      challenge_id: init.body.challenge_id,
      voucher: CREDENTIAL,
    });

    expect(response.status).toBe(401);
    expect(getKey).not.toHaveBeenCalled();
    expect(checkState).not.toHaveBeenCalled();
  });

  it('never contacts the mint when the signature is not over this body', async () => {
    // The credential is swapped in after signing, so the payload hash no longer
    // matches. The proof inside is well-formed and would be state-checked if
    // the ordering were wrong.
    const { app, getKey, checkState } = build();
    const init = await send(app, '/auth/init').send({ npub: NPUB });
    const built = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(PK),
      createdAt: NOW,
    });

    const response = await send(app, '/auth/complete')
      .set('authorization', built.authorization)
      .set('content-type', 'application/json')
      .send(JSON.stringify({ challenge_id: init.body.challenge_id, voucher: CREDENTIAL }));

    expect(response.status).toBe(401);
    expect(getKey).not.toHaveBeenCalled();
    expect(checkState).not.toHaveBeenCalled();
  });

  it('never contacts the mint for an unknown challenge', async () => {
    const { app, getKey, checkState } = build();

    const response = await send(app, '/auth/complete').send({
      challenge_id: 'no-such-challenge',
      voucher: CREDENTIAL,
    });

    expect(response.status).toBe(401);
    expect(getKey).not.toHaveBeenCalled();
    expect(checkState).not.toHaveBeenCalled();
  });

  it('does reach the mint once the caller has proven key control', async () => {
    // The counterweight. Without this, the tests above would pass equally well
    // if the voucher path were never wired up at all.
    const { app, getKey } = build();
    const init = await send(app, '/auth/init').send({ npub: NPUB });
    const built = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(PK),
      createdAt: NOW,
      voucher: CREDENTIAL,
    });

    await send(app, '/auth/complete')
      .set('authorization', built.authorization)
      .set('content-type', 'application/json')
      .send(new TextDecoder().decode(built.rawBody));

    // The mint really is reached on an authenticated completion. Without this
    // assertion the three tests above would pass just as well if the voucher
    // path were never wired up at all -- "the mint was not contacted" is only
    // evidence of ordering if something can contact it.
    expect(getKey).toHaveBeenCalledWith(MINT, CREDENTIAL.keyset_id, CREDENTIAL.amount);
  });
});
