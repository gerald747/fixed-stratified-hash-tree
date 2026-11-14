# fixed-stratified-hash-tree

A zero-dependency binary hash tree with a fixed depth: leaves are hashed in order, paired bottom-up, and a membership proof can be checked against a known root hash.

```js
import { FixedStratifiedHashTree, sha256Hex } from './src/index.js';

const tree = new FixedStratifiedHashTree(2); // 4 leaves
tree.setLeaf(0, sha256Hex('alice'));
tree.setLeaf(1, sha256Hex('bob'));
tree.setLeaf(2, sha256Hex('carol'));
tree.setLeaf(3, sha256Hex('dave'));

const root = tree.buildRoot();
const proof = tree.prove(2);

console.log(root);
console.log(FixedStratifiedHashTree.verify(root, tree.getLeaf(2), proof)); // true
console.log(FixedStratifiedHashTree.verify(root, tree.getLeaf(2), tree.prove(3))); // false
```

## Why this exists

A plain Merkle tree grows to whatever size its data happens to be, which makes proof lengths variable. When proofs are exchanged over a fixed-size channel or stored in a fixed-size field, variable length is annoying. Fixing the depth at construction time makes every proof exactly `depth` steps long, and the leaf count exactly `2^depth`.

The trade-off is that you must know the depth up front, and every leaf slot must be filled before the root can be built. If you have a sparse set of leaves, this library is the wrong shape; it wants a dense, fixed-size set. In return you get constant-size proofs and a root that is cheap to recompute.

## Edge to be aware of

Leaves are not sorted or deduplicated. The order you call `setLeaf` in is the order used for hashing, so two trees containing the same values in different positions have different roots. That is deliberate: position is part of what the root commits to. If you need a canonical set, sort your leaves before inserting them.

A second edge: `buildRoot` throws if any leaf slot is still unset. There is no implicit empty-leaf hash, because silently hashing zeros would make a tree with missing data indistinguishable from one with deliberate zero leaves.

## API

- `new FixedStratifiedHashTree(depth)` — `depth` is a non-negative integer; the tree holds `2^depth` leaves. Depth is capped at 30.
- `tree.setLeaf(index, hashHex)` — set a leaf to a 64-character hex string. Uppercase is normalised to lowercase. Throws if the index is out of range or the hash is malformed.
- `tree.getLeaf(index)` — returns the stored hex string, or `null` if unset.
- `tree.buildRoot()` — computes and returns the root hash. Throws if any leaf is unset. Calling it again after a `setLeaf` recomputes.
- `tree.root` — the last built root, or `null`.
- `tree.prove(index)` — returns an array of `{ side, hash }` steps from the leaf up to the root. Throws if the root has not been built.
- `FixedStratifiedHashTree.verify(rootHex, leafHashHex, proof)` — returns `true` only when the proof reconstructs `rootHex` from `leafHashHex`. Malformed inputs return `false` rather than throwing.
- `sha256Hex(input)` — helper that returns the lowercase hex SHA-256 of a string or `Uint8Array`.
- `hexToBytes(hex)` / `bytesToHex(bytes)` — conversion helpers used by the tree.
