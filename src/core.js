import { createHash } from 'node:crypto';

/**
 * Fixed Stratified Hash Tree.
 *
 * Leaves are supplied in order and paired bottom-up into a binary tree of a
 * fixed depth. The depth is fixed at construction time so that membership
 * proofs have a constant, predictable length and can be checked against a
 * known root hash without needing the full leaf set.
 *
 * Design choice: leaves are not sorted or deduplicated. The caller controls
 * the ordering, which keeps the structure deterministic and cheap to build.
 * The trade-off is that two trees with the same leaves in different orders
 * have different roots; this is intentional because ordering can carry
 * meaning (e.g. transaction index).
 */

export function sha256Hex(input) {
  const h = createHash('sha256');
  h.update(input);
  return h.digest('hex');
}

export function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('hex must be a string');
  }
  if (hex.length % 2 !== 0) {
    throw new Error('hex string must have even length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error('invalid hex character');
    }
    out[i] = byte;
  }
  return out;
}

function hashPair(leftHex, rightHex) {
  const left = hexToBytes(leftHex);
  const right = hexToBytes(rightHex);
  const buf = new Uint8Array(left.length + right.length);
  buf.set(left, 0);
  buf.set(right, left.length);
  return sha256Hex(buf);
}

function isPowerOfTwo(n) {
  return n > 0 && (n & (n - 1)) === 0;
}

export class FixedStratifiedHashTree {
  /**
   * @param {number} depth number of levels above the leaves; total leaves = 2^depth
   */
  constructor(depth) {
    if (!Number.isInteger(depth) || depth < 0) {
      throw new Error('depth must be a non-negative integer');
    }
    if (depth > 30) {
      // Guards against accidental allocation of absurdly large arrays.
      throw new Error('depth too large');
    }
    this.depth = depth;
    this.leafCount = 2 ** depth;
    this._leaves = new Array(this.leafCount).fill(null);
    this._root = null;
  }

  get root() {
    return this._root;
  }

  /**
   * Set the hash for a leaf position. The value must be a 64-character hex
   * string (a SHA-256 digest) to keep proof verification simple and consistent.
   */
  setLeaf(index, hashHex) {
    if (!Number.isInteger(index) || index < 0 || index >= this.leafCount) {
      throw new Error('leaf index out of range');
    }
    if (typeof hashHex !== 'string' || !/^[0-9a-f]{64}$/i.test(hashHex)) {
      throw new Error('leaf hash must be a 64-character hex string');
    }
    this._leaves[index] = hashHex.toLowerCase();
    this._root = null;
  }

  getLeaf(index) {
    if (!Number.isInteger(index) || index < 0 || index >= this.leafCount) {
      throw new Error('leaf index out of range');
    }
    return this._leaves[index];
  }

  /**
   * Compute the root hash. All leaves must be set; a missing leaf is an error
   * because a partially filled tree has no meaningful root.
   */
  buildRoot() {
    for (let i = 0; i < this.leafCount; i++) {
      if (this._leaves[i] === null) {
        throw new Error(`leaf ${i} is not set`);
      }
    }
    let level = this._leaves.slice();
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(hashPair(level[i], level[i + 1]));
      }
      level = next;
    }
    this._root = level[0];
    return this._root;
  }

  /**
   * Produce a membership proof for a leaf. The proof is a list of sibling
   * hashes from the leaf level up to the root, each tagged with which side the
   * sibling sits on.
   */
  prove(index) {
    if (!Number.isInteger(index) || index < 0 || index >= this.leafCount) {
      throw new Error('leaf index out of range');
    }
    if (this._root === null) {
      throw new Error('root has not been built');
    }
    const proof = [];
    let level = this._leaves.slice();
    let idx = index;
    while (level.length > 1) {
      const siblingIdx = idx ^ 1;
      const sibling = level[siblingIdx];
      proof.push({
        side: idx % 2 === 0 ? 'right' : 'left',
        hash: sibling,
      });
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(hashPair(level[i], level[i + 1]));
      }
      level = next;
      idx = Math.floor(idx / 2);
    }
    return proof;
  }

  /**
   * Verify a proof against a root. Returns true only when the recomputed root
   * matches exactly.
   */
  static verify(rootHex, leafHashHex, proof) {
    if (typeof rootHex !== 'string' || !/^[0-9a-f]{64}$/i.test(rootHex)) {
      return false;
    }
    if (typeof leafHashHex !== 'string' || !/^[0-9a-f]{64}$/i.test(leafHashHex)) {
      return false;
    }
    if (!Array.isArray(proof)) {
      return false;
    }
    let current = leafHashHex.toLowerCase();
    for (const step of proof) {
      if (!step || typeof step !== 'object') {
        return false;
      }
      const { side, hash } = step;
      if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/i.test(hash)) {
        return false;
      }
      if (side === 'left') {
        current = hashPair(hash.toLowerCase(), current);
      } else if (side === 'right') {
        current = hashPair(current, hash.toLowerCase());
      } else {
        return false;
      }
    }
    return current === rootHex.toLowerCase();
  }
}
