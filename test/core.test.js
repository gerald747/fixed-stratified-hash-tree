import test from 'node:test';
import assert from 'node:assert/strict';
import { FixedStratifiedHashTree, sha256Hex } from '../src/index.js';

function leaf(label) {
  return sha256Hex(label);
}

test('builds a root from a full set of leaves', () => {
  const tree = new FixedStratifiedHashTree(2);
  tree.setLeaf(0, leaf('a'));
  tree.setLeaf(1, leaf('b'));
  tree.setLeaf(2, leaf('c'));
  tree.setLeaf(3, leaf('d'));
  const root = tree.buildRoot();
  assert.equal(typeof root, 'string');
  assert.equal(root.length, 64);
  assert.equal(tree.root, root);
});

test('root is order sensitive', () => {
  const t1 = new FixedStratifiedHashTree(1);
  t1.setLeaf(0, leaf('a'));
  t1.setLeaf(1, leaf('b'));
  const r1 = t1.buildRoot();

  const t2 = new FixedStratifiedHashTree(1);
  t2.setLeaf(0, leaf('b'));
  t2.setLeaf(1, leaf('a'));
  const r2 = t2.buildRoot();

  assert.notEqual(r1, r2);
});

test('proof verifies for every leaf', () => {
  const tree = new FixedStratifiedHashTree(3);
  for (let i = 0; i < 8; i++) {
    tree.setLeaf(i, leaf(`leaf-${i}`));
  }
  const root = tree.buildRoot();
  for (let i = 0; i < 8; i++) {
    const proof = tree.prove(i);
    assert.equal(FixedStratifiedHashTree.verify(root, tree.getLeaf(i), proof), true, `leaf ${i}`);
  }
});

test('proof fails for a different leaf', () => {
  const tree = new FixedStratifiedHashTree(2);
  for (let i = 0; i < 4; i++) {
    tree.setLeaf(i, leaf(`x-${i}`));
  }
  const root = tree.buildRoot();
  const proof = tree.prove(0);
  assert.equal(FixedStratifiedHashTree.verify(root, leaf('not-in-tree'), proof), false);
});

test('proof fails for a different root', () => {
  const tree = new FixedStratifiedHashTree(2);
  for (let i = 0; i < 4; i++) {
    tree.setLeaf(i, leaf(`y-${i}`));
  }
  const root = tree.buildRoot();
  const proof = tree.prove(1);
  const otherRoot = sha256Hex('other-root');
  assert.equal(FixedStratifiedHashTree.verify(otherRoot, tree.getLeaf(1), proof), false);
});

test('proof fails when a sibling hash is corrupted', () => {
  const tree = new FixedStratifiedHashTree(2);
  for (let i = 0; i < 4; i++) {
    tree.setLeaf(i, leaf(`z-${i}`));
  }
  const root = tree.buildRoot();
  const proof = tree.prove(2);
  const badProof = proof.map((step, i) => (i === 0 ? { ...step, hash: leaf('tampered') } : step));
  assert.equal(FixedStratifiedHashTree.verify(root, tree.getLeaf(2), badProof), false);
});

test('verify rejects malformed inputs', () => {
  const tree = new FixedStratifiedHashTree(1);
  tree.setLeaf(0, leaf('p'));
  tree.setLeaf(1, leaf('q'));
  const root = tree.buildRoot();
  const proof = tree.prove(0);
  assert.equal(FixedStratifiedHashTree.verify('not-hex', tree.getLeaf(0), proof), false);
  assert.equal(FixedStratifiedHashTree.verify(root, 'short', proof), false);
  assert.equal(FixedStratifiedHashTree.verify(root, tree.getLeaf(0), null), false);
  assert.equal(FixedStratifiedHashTree.verify(root, tree.getLeaf(0), [{ side: 'up', hash: leaf('r') }]), false);
});

test('buildRoot throws when a leaf is missing', () => {
  const tree = new FixedStratifiedHashTree(1);
  tree.setLeaf(0, leaf('m'));
  assert.throws(() => tree.buildRoot(), /leaf 1 is not set/);
});

test('prove throws before the root is built', () => {
  const tree = new FixedStratifiedHashTree(1);
  tree.setLeaf(0, leaf('m'));
  tree.setLeaf(1, leaf('n'));
  assert.throws(() => tree.prove(0), /root has not been built/);
});

test('setLeaf rejects out of range and bad hashes', () => {
  const tree = new FixedStratifiedHashTree(1);
  assert.throws(() => tree.setLeaf(2, leaf('a')), /out of range/);
  assert.throws(() => tree.setLeaf(-1, leaf('a')), /out of range/);
  assert.throws(() => tree.setLeaf(0, 'xyz'), /64-character hex/);
  assert.throws(() => tree.setLeaf(0, 123), /64-character hex/);
});

test('depth zero is a single leaf tree', () => {
  const tree = new FixedStratifiedHashTree(0);
  const h = leaf('solo');
  tree.setLeaf(0, h);
  const root = tree.buildRoot();
  assert.equal(root, h);
  const proof = tree.prove(0);
  assert.deepEqual(proof, []);
  assert.equal(FixedStratifiedHashTree.verify(root, h, proof), true);
});

test('constructor rejects invalid depths', () => {
  assert.throws(() => new FixedStratifiedHashTree(-1), /non-negative integer/);
  assert.throws(() => new FixedStratifiedHashTree(1.5), /non-negative integer/);
  assert.throws(() => new FixedStratifiedHashTree(31), /too large/);
});

test('setLeaf accepts uppercase hex and normalises it', () => {
  const tree = new FixedStratifiedHashTree(1);
  const h = leaf('upper').toUpperCase();
  tree.setLeaf(0, h);
  assert.equal(tree.getLeaf(0), h.toLowerCase());
});

test('getLeaf returns null for an unset leaf', () => {
  const tree = new FixedStratifiedHashTree(2);
  assert.equal(tree.getLeaf(3), null);
});
