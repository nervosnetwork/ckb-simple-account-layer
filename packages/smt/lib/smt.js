const blake2b = require("blake2b");
const { Reader } = require("ckb-js-toolkit");

function hash(...values) {
  const hasher = blake2b(
    32,
    null,
    null,
    new Uint8Array(Reader.fromRawString("ckb-default-hash").toArrayBuffer())
  );
  for (const value of values) {
    hasher.update(new Uint8Array(new Reader(value).toArrayBuffer()));
  }
  const out = new Uint8Array(32);
  hasher.digest(out);
  return out.buffer;
}

function allZero(buffer) {
  const array = new Uint8Array(buffer.slice(0));
  for (let i = 0; i < array.length; i++) {
    if (array[i] !== 0) {
      return false;
    }
  }
  return true;
}

function flipBit(buffer, offset) {
  const array = new Uint8Array(buffer.slice(0));
  const byteOffset = Math.floor(offset / 8);
  const value = array[byteOffset];
  const newValue = value ^ (0x80 >> offset % 8);
  array[byteOffset] = newValue;
  return array.buffer;
}

function clearBit(buffer, offset) {
  const array = new Uint8Array(buffer.slice(0));
  const byteOffset = Math.floor(offset / 8);
  const value = array[byteOffset];
  const newValue = value & (0xff ^ (0x80 >> offset % 8));
  array[byteOffset] = newValue;
  return array.buffer;
}

function isBitSet(buffer, offset) {
  const array = new Uint8Array(buffer);
  const byteOffset = Math.floor(offset / 8);
  const value = array[byteOffset];
  return (value & (0x80 >> offset % 8)) !== 0;
}

function siblingKey(buffer, length) {
  const resultBuffer = new ArrayBuffer(4 + buffer.byteLength);
  const array = new Uint8Array(resultBuffer);
  const view = new DataView(resultBuffer);
  view.setUint32(0, length, true);
  array.set(new Uint8Array(buffer), 4);
  return new Reader(resultBuffer).serializeJson();
}

class SparseMerkleTree {
  constructor() {
    this.branches = {};
    this.leaves = {};
    this.rootHash = Buffer.alloc(32, 0).buffer;
  }

  currentRootHash() {
    return this.rootHash;
  }

  fetch(key) {
    key = new Reader(key).serializeJson();
    return this.leaves[key];
  }

  update(key, value) {
    const keyReader = new Reader(key);
    const valueReader = new Reader(value);
    if (keyReader.length() !== 32 || valueReader.length() !== 32) {
      throw new Error("Key and value must be buffer of 32 bytes length!");
    }
    const valueBuffer = valueReader.toArrayBuffer();
    if (allZero(valueBuffer)) {
      return this.del(key);
    }
    this.leaves[keyReader.serializeJson()] = valueBuffer;
    let currentKey = keyReader.toArrayBuffer();
    let currentHash = hash(currentKey, valueBuffer);
    for (let i = 255; i >= 0; i--) {
      this.branches[siblingKey(currentKey, i + 1)] = currentHash;
      const sibling = flipBit(currentKey, i);
      const siblingValue = this.branches[siblingKey(sibling, i + 1)];
      if (siblingValue) {
        if (isBitSet(currentKey, i)) {
          currentHash = hash(siblingValue, currentHash);
        } else {
          currentHash = hash(currentHash, siblingValue);
        }
      }
      currentKey = clearBit(currentKey, i);
    }
    this.rootHash = currentHash;
  }

  del(key) {
    const keyReader = newReader(key);
    if (keyReader.length() !== 32) {
      throw new Error("Key must be buffer of 32 bytes length!");
    }
    delete this.leaves[keyReader.serializeJson()];
    let currentHash = null;
    for (let i = 255; i >= 0; i--) {
      this.branches[siblingKey(currentKey, i + 1)] = currentHash;
      const sibling = flipBit(currentKey, i);
      const siblingValue = this.branches[(siblingKey(sibling), i + 1)];
      if (siblingValue && currentHash) {
        if (isBitSet(currentKey, i)) {
          currentHash = hash(siblingValue, currentHash);
        } else {
          currentHash = hash(currentHash, siblingValue);
        }
      } else if (siblingValue) {
        currentHash = siblingValue;
      }
      currentKey = clearBit(currentKey, i);
    }
    this.rootHash = currentHash || Buffer.alloc(32, 0).buffer;
  }

  proof(key) {
    let mask = Buffer.alloc(32, 0).buffer;
    let totalLength = 32;
    let data = [];
    let currentKey = key;
    for (let i = 255; i >= 0; i--) {
      const sibling = flipBit(currentKey, i);
      const branchValue = this.branches[siblingKey(sibling, i + 1)];
      if (branchValue) {
        /* Proof is in reverse order to ease verification */
        data.push(branchValue);
        mask = flipBit(mask, 255 - i);
        totalLength += 32;
      }
      currentKey = clearBit(currentKey, i);
    }
    const array = new Uint8Array(totalLength);
    array.set(new Uint8Array(mask), 0);
    for (let i = 0; i < data.length; i++) {
      array.set(new Uint8Array(data[i]), 32 + i * 32);
    }
    return array.buffer;
  }

  verify(key, value, proof) {
    return SparseMerkleTree.verify(key, value, proof, this.rootHash);
  }

  static verify(key, value, proof, rootHash) {
    const keyReader = new Reader(key);
    if (keyReader.length() !== 32) {
      throw new Error("Key must be buffer of 32 bytes length!");
    }
    key = keyReader.toArrayBuffer();
    value = new Reader(value).toArrayBuffer();
    proof = new Reader(proof).toArrayBuffer();
    if (!SparseMerkleTree.verifyProofLength(proof)) {
      throw new Error("Invalid proof length!");
    }
    let currentHash = null;
    if (value) {
      currentHash = hash(key, value);
    }
    let currentOffset = 32;
    for (let i = 0; i < 256; i++) {
      if (isBitSet(proof, i)) {
        /* Note we are calculating upwards from leaf to root */
        if (isBitSet(key, 255 - i)) {
          currentHash = hash(
            proof.slice(currentOffset, currentOffset + 32),
            currentHash
          );
        } else {
          currentHash = hash(
            currentHash,
            proof.slice(currentOffset, currentOffset + 32)
          );
        }
        currentOffset += 32;
      }
    }
    return (
      new Reader(rootHash).serializeJson() ===
      new Reader(currentHash).serializeJson()
    );
  }

  static verifyProofLength(proof) {
    if (proof.byteLength < 32) {
      return false;
    }
    let totalLength = 32;
    for (let i = 0; i < 256; i++) {
      if (isBitSet(proof, i)) {
        totalLength += 32;
      }
    }
    return totalLength === proof.byteLength;
  }
}

module.exports = SparseMerkleTree;
