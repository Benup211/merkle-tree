// merkle-snapshot.js
//
// Off-chain Merkle snapshot + vote-proof generator matching the TusdtGovernance contract:
//
//   leaf  = blake2b_256( SCALE(coldkey, hotkey, balance_u128, multiplier_bps_u32) )
//   node  = blake2b_256( min(a,b) ++ max(a,b) )       // sorted-pair, OpenZeppelin style
//   root  = fold up; an odd node at any level is promoted unchanged to the next level
//
// On-chain verification simply folds: computed = hash_pair(computed, sibling) for each
// proof element, so the proof is just the list of sibling hashes bottom-up (no position flags).
//
// SCALE encoding of the tuple is the plain concatenation of:
//   coldkey:        32 raw bytes (AccountId)
//   hotkey:         32 raw bytes (AccountId)
//   balance:        u128, 16 bytes little-endian
//   multiplier_bps: u32,   4 bytes little-endian
//
// deps:  npm install @polkadot/util-crypto @polkadot/util
//        (decodeAddress turns an SS58 address into its raw 32-byte AccountId;
//         blake2AsU8a is blake2b with a 256-bit digest, same as ink!'s Blake2x256)

const { blake2AsU8a, decodeAddress } = require('@polkadot/util-crypto');
const { u8aToHex } = require('@polkadot/util');

// ---------------------------------------------------------------------------
// SCALE encoding helpers
// ---------------------------------------------------------------------------

/** u128 -> 16-byte little-endian Uint8Array (SCALE fixed-width encoding). */
function encodeU128LE(value) {
  let v = BigInt(value);
  if (v < 0n || v > (1n << 128n) - 1n) throw new Error('balance out of u128 range');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** u32 -> 4-byte little-endian Uint8Array (SCALE fixed-width encoding). */
function encodeU32LE(value) {
  if (value < 0 || value > 0xffffffff) throw new Error('multiplier_bps out of u32 range');
  const out = new Uint8Array(4);
  out[0] = value & 0xff;
  out[1] = (value >>> 8) & 0xff;
  out[2] = (value >>> 16) & 0xff;
  out[3] = (value >>> 24) & 0xff;
  return out;
}

/** Accepts an SS58 string or a 32-byte Uint8Array/hex and returns raw 32 bytes. */
function toAccountIdBytes(account) {
  if (account instanceof Uint8Array) {
    if (account.length !== 32) throw new Error('AccountId must be 32 bytes');
    return account;
  }
  return decodeAddress(account); // handles SS58 and 0x-hex
}

function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Hashing — must mirror helpers.rs exactly
// ---------------------------------------------------------------------------

/** leaf_hash(coldkey, hotkey, balance, multiplier_bps) */
function leafHash({ coldkey, hotkey, balance, multiplierBps }) {
  const encoded = concatBytes(
    toAccountIdBytes(coldkey),
    toAccountIdBytes(hotkey),
    encodeU128LE(balance),
    encodeU32LE(multiplierBps),
  );
  return blake2AsU8a(encoded, 256);
}

/** Byte-lexicographic compare of two 32-byte hashes (matches Rust's [u8;32] Ord). */
function compareHashes(a, b) {
  for (let i = 0; i < 32; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

/** hash_pair(a, b): blake2b_256(min(a,b) ++ max(a,b)) */
function hashPair(a, b) {
  const [lo, hi] = compareHashes(a, b) <= 0 ? [a, b] : [b, a];
  return blake2AsU8a(concatBytes(lo, hi), 256);
}

// ---------------------------------------------------------------------------
// Tree construction & proofs
// ---------------------------------------------------------------------------

/**
 * Builds the full tree from snapshot entries.
 *
 * entries: [{ coldkey, hotkey, balance, multiplierBps }, ...]
 * Returns { root, levels, leaves } where levels[0] = leaves, levels[last] = [root].
 *
 * Odd-node rule: a level with an odd count promotes its last node unchanged.
 * The on-chain verifier just folds the supplied siblings, so this convention only
 * has to be consistent between root construction and proof generation — and it is.
 */
function buildTree(entries) {
  if (entries.length === 0) throw new Error('snapshot must have at least one entry');
  const leaves = entries.map(leafHash);
  const levels = [leaves];

  let current = leaves;
  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(hashPair(current[i], current[i + 1]));
      } else {
        next.push(current[i]); // odd node promoted unchanged
      }
    }
    levels.push(next);
    current = next;
  }

  return { root: current[0], levels, leaves };
}

/**
 * Generates the bottom-up sibling proof for the leaf at `leafIndex`.
 * Levels where the node was promoted (no sibling) contribute nothing.
 */
function getProof(tree, leafIndex) {
  const proof = [];
  let index = leafIndex;
  for (let level = 0; level < tree.levels.length - 1; level++) {
    const nodes = tree.levels[level];
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    if (siblingIndex < nodes.length) {
      proof.push(nodes[siblingIndex]);
    }
    index = Math.floor(index / 2);
  }
  return proof;
}

/** Local mirror of the on-chain verify_merkle_proof, for sanity checking. */
function verifyProof(proof, root, leaf) {
  let computed = leaf;
  for (const sibling of proof) {
    computed = hashPair(computed, sibling);
  }
  return compareHashes(computed, root) === 0;
}

// ---------------------------------------------------------------------------
// Example usage
// ---------------------------------------------------------------------------

function main() {
  // The off-chain snapshot: one entry per eligible (coldkey, hotkey) pair, with the
  // alpha balance frozen at the snapshot block and the time-staked multiplier in bps.
  // Order matters only for proof indexing; the committed root must come from this exact list.
  const HOTKEY = '5G78yVDm34C7jUM4cAJaAJnE7WhVxVPkxwMhWDt1HF6omcYA';
  const snapshot = [
    { coldkey: '5GHoStNXsJwVXrjUCD4XtkoW6uSfreWZdMcKvvG9kh7ipPBy', hotkey: HOTKEY, balance: 50_000_000_000n, multiplierBps: 10_000 },
    { coldkey: '5G78yVDm34C7jUM4cAJaAJnE7WhVxVPkxwMhWDt1HF6omcYA', hotkey: HOTKEY, balance: 40_000_000_000n, multiplierBps: 10_000 },
    { coldkey: '5FW1Cj4QgRpRL3DA68QxPLvAJNnoePSHsZ3g83S9K6pBAGka', hotkey: HOTKEY, balance: 50_000_000_000n, multiplierBps: 10_000 },
    { coldkey: '5Cm5gawJgfMp6UDcbyjBUu8Xtvg8bbaqqRb5qsVMFrjZn1Yd', hotkey: HOTKEY, balance: 40_000_000_000n, multiplierBps: 10_000 },
    { coldkey: '5H9YPS9FJX6nbFXkm9zVhoySJBX9RRfWF36abisNz5Ps9YaX', hotkey: HOTKEY, balance: 20_000_000_000n, multiplierBps: 10_000 },
    { coldkey: '5EnprsS8GfaHAVKYSkLgtrrjhtdP3xChkkrMrbDxi3o7BMHF', hotkey: HOTKEY, balance: 100_000_000_000n, multiplierBps: 10_000 },
  ];

  // 1. Build the tree. A council member commits `root` (plus the circulating supply
  //    and snapshot block) via governance.submit_snapshot(root, circulating_supply, block).
  const tree = buildTree(snapshot);
  console.log('='.repeat(78));
  console.log('Merkle root (submit_snapshot):', u8aToHex(tree.root));
  console.log('='.repeat(78));

  // 2. For every leaf, generate its proof and print the exact vote() arguments.
  //
  //    IMPORTANT: each vote transaction MUST be signed by that leaf's coldkey — the
  //    contract recomputes the leaf using env().caller() as the coldkey, so a
  //    different signer (or a different hotkey/balance/multiplier than what was
  //    committed in the snapshot) fails with InvalidProof.
  //
  //    Proof lengths can differ between leaves: a leaf whose branch was promoted
  //    at some level (odd node count) has a shorter proof. Supply exactly the
  //    items printed — no more, no fewer.
  snapshot.forEach((voter, i) => {
    const proof = getProof(tree, i);
    const leaf = tree.leaves[i];

    if (!verifyProof(proof, tree.root, leaf)) {
      throw new Error(`leaf ${i} failed verification — tree/proof logic is inconsistent`);
    }

    console.log(`\n[leaf ${i}] sign the vote tx with coldkey: ${voter.coldkey}`);
    console.log(`  leaf hash      : ${u8aToHex(leaf)}`);
    console.log('  vote() arguments:');
    console.log(`    proposalId   : <your proposal id>`);
    console.log(`    hotkey       : ${voter.hotkey}`);
    console.log(`    support      : true | false`);
    console.log(`    balance      : ${voter.balance.toString()}`);
    console.log(`    multiplierBps: ${voter.multiplierBps}`);
    console.log(`    proof        : ${proof.length} item(s)`);
    proof.forEach((p, j) => console.log(`      proof[${j}]   : ${u8aToHex(p)}`));
  });

  console.log(`\nAll ${snapshot.length} leaves verified against the root.`);

  // 3. Machine-readable dump (e.g. for a voting frontend): writes vote-proofs.json
  //    with the root and per-coldkey vote arguments.
  const dump = {
    merkle_root: u8aToHex(tree.root),
    leaves: snapshot.map((voter, i) => ({
      coldkey: voter.coldkey, // must be the tx signer
      vote_args: {
        hotkey: voter.hotkey,
        balance: voter.balance.toString(),
        multiplier_bps: voter.multiplierBps,
        // NOTE: must be `(p) => u8aToHex(p)`, NOT `.map(u8aToHex)` — map passes the
        // array index as u8aToHex's second (bitLength) argument, which abbreviates
        // every element after the first to "0x…XX".
        proof: getProof(tree, i).map((p) => u8aToHex(p)),
      },
    })),
  };
  require('fs').writeFileSync('vote-proofs.json', JSON.stringify(dump, null, 2));
  console.log('Wrote vote-proofs.json');
}

if (require.main === module) main();

module.exports = { leafHash, hashPair, buildTree, getProof, verifyProof };