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
  const snapshot = [
    {
      coldkey: '5EnprsS8GfaHAVKYSkLgtrrjhtdP3xChkkrMrbDxi3o7BMHF',
      hotkey:  '5CqRMuYSSqYkSa8AM3VawVfdyUhyBufyesvvgh3vCgaGb9Ed',
      balance: 1_000_000_000n,
      multiplierBps: 10_000,
    },
    {
      coldkey: '5G78yVDm34C7jUM4cAJaAJnE7WhVxVPkxwMhWDt1HF6omcYA',
      hotkey:  '5CqRMuYSSqYkSa8AM3VawVfdyUhyBufyesvvgh3vCgaGb9Ed',
      balance: 1_000_000_000n,
      multiplierBps: 10_000,
    },
    {
      coldkey: '5FW1Cj4QgRpRL3DA68QxPLvAJNnoePSHsZ3g83S9K6pBAGka',
      hotkey:  '5CqRMuYSSqYkSa8AM3VawVfdyUhyBufyesvvgh3vCgaGb9Ed',
      balance: 1_000_000_000n,
      multiplierBps: 10_000,
    },
  ];

  // 1. Build the tree. A council member commits `root` (plus the circulating supply
  //    and snapshot block) via governance.submit_snapshot(root, circulating_supply, block).
  const tree = buildTree(snapshot);
  console.log('Merkle root (submit_snapshot):', u8aToHex(tree.root));

  // 2. A voter generates the proof for their own leaf.
  const voterIndex = 0;
  const voter = snapshot[voterIndex];
  const proof = getProof(tree, voterIndex);
  const leaf = tree.leaves[voterIndex];

  console.log('\nVoter leaf:', u8aToHex(leaf));
  console.log('Proof:', proof.map(u8aToHex));
  console.log('Local verify:', verifyProof(proof, tree.root, leaf)); // must be true

  // 3. What to supply to governance.vote(...):
  //    - the transaction MUST be signed by the coldkey (the contract uses env().caller()
  //      as the coldkey when recomputing the leaf — a mismatched signer fails the proof)
  console.log('\nvote() arguments:');
  console.log({
    proposal_id: 1,
    hotkey: voter.hotkey,                  // AccountId
    support: true,                         // bool
    balance: voter.balance.toString(),     // u128, must equal the snapshot-frozen value
    multiplier_bps: voter.multiplierBps,   // u32, must equal the snapshot value
    proof: proof.map(u8aToHex),            // Vec<[u8; 32]>
  });

  // Sanity: every leaf must verify against the root.
  snapshot.forEach((_, i) => {
    const ok = verifyProof(getProof(tree, i), tree.root, tree.leaves[i]);
    if (!ok) throw new Error(`leaf ${i} failed verification`);
  });
  console.log('\nAll', snapshot.length, 'leaves verify against the root.');
}

if (require.main === module) main();

module.exports = { leafHash, hashPair, buildTree, getProof, verifyProof };