import { blake2AsU8a, decodeAddress } from "@polkadot/util-crypto";
import { TypeRegistry } from "@polkadot/types";
import { u8aToHex } from "@polkadot/util";

const snapshot = [
  {
    coldkey: "5EnprsS8GfaHAVKYSkLgtrrjhtdP3xChkkrMrbDxi3o7BMHF",
    hotkey: "5CqRMuYSSqYkSa8AM3VawVfdyUhyBufyesvvgh3vCgaGb9Ed",
    balance: 1_000_000_000_000n,
    multiplier_bps: 10000,
  },
  {
    coldkey: "5HjDHr8yrnSruQPRDW7H7DtBoWZrVqsmBgSADVKU4Bk47L2R",
    hotkey: "5CqRMuYSSqYkSa8AM3VawVfdyUhyBufyesvvgh3vCgaGb9Ed",
    balance: 2_500_000_000_000n,
    multiplier_bps: 10000,
  },
  {
    coldkey: "5GNCaCvkwGFDDkDXo72k5wN2gTJmXq2BeXWPG2PBvUXKpiW8",
    hotkey: "5CqRMuYSSqYkSa8AM3VawVfdyUhyBufyesvvgh3vCgaGb9Ed",
    balance: 500_000_000_000n,
    multiplier_bps: 10000,
  },
  {
    coldkey: "5DvdKitpnMsV2PETQhwoWpndCcKHr99X7KtkKLEyieX7vJ6r",
    hotkey: "5CqRMuYSSqYkSa8AM3VawVfdyUhyBufyesvvgh3vCgaGb9Ed",
    balance: 8_000_000_000_000n,
    multiplier_bps: 10000,
  },
];

const registry = new TypeRegistry();

type SnapshotEntry = {
  coldkey: string;
  hotkey: string;
  balance: bigint;
  multiplier_bps: number;
};

function leafHash(entry: SnapshotEntry): Uint8Array {
  const encoded = registry
    .createType(
      "(AccountId32,AccountId32,u128,u32)",
      [
        decodeAddress(entry.coldkey),
        decodeAddress(entry.hotkey),
        entry.balance,
        entry.multiplier_bps,
      ]
    )
    .toU8a();

  return blake2AsU8a(encoded, 256);
}

function hashPair(a: Uint8Array, b: Uint8Array): Uint8Array {
  const sorted =
    Buffer.compare(Buffer.from(a), Buffer.from(b)) <= 0
      ? [a, b]
      : [b, a];

  const combined = new Uint8Array(64);

  combined.set(sorted[0], 0);
  combined.set(sorted[1], 32);

  return blake2AsU8a(combined, 256);
}

function buildMerkleRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) {
    return new Uint8Array(32);
  }

  let level = [...leaves];

  while (level.length > 1) {
    const next: Uint8Array[] = [];

    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(hashPair(level[i], level[i + 1]));
      } else {
        next.push(level[i]);
      }
    }

    level = next;
  }

  return level[0];
}

const leaves = snapshot.map(leafHash);

const root = buildMerkleRoot(leaves);

console.log("Merkle Root:", u8aToHex(root));


function generateProof(
  leaves: Uint8Array[],
  targetIndex: number
): Uint8Array[] {
  const proof: Uint8Array[] = [];

  let level = [...leaves];
  let index = targetIndex;

  while (level.length > 1) {
    const siblingIndex =
      index % 2 === 0
        ? index + 1
        : index - 1;

    if (siblingIndex < level.length) {
      proof.push(level[siblingIndex]);
    }

    const next: Uint8Array[] = [];

    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(hashPair(level[i], level[i + 1]));
      } else {
        next.push(level[i]);
      }
    }

    index = Math.floor(index / 2);
    level = next;
  }

  return proof;
}


const proof = generateProof(leaves, 0);

console.log(
  proof.map((p) => u8aToHex(p))
);


console.log([...root])