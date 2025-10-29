

### **SOLAVIA v8 CLI — Deterministic AI Runtime + Provenance (Merkle & Signature)**

> Author: James Chapman
>Email: iconoclastdao@gmail.com

> Runtime: **Node.js ≥ 18 / ESM modules**

---

# 1. Overview

**Solavia** is a deterministic execution runtime for AI/automation pipelines.
It guarantees:

* Deterministic execution with seeded randomness
* Merkle-based provenance of every stage (`input → deterministic output`)
* Optional cryptographic signature of the Merkle proof
* Reproducibility via snapshots and rollbacks to any historical pipeline state
* Zero dependencies (pure Node.js & core crypto)

---

# 2. File Structure

```
solavia/
 ├── solavia.js            ← (this file, CLI entry)
 ├── solavia-core.js       ← Merkle / hashing / provenance engine
 ├── pipelines/
 |      └── mypipeline.js  ← Example user workflow
 └── key.pem               ← Optional signing key (PEM format)
```

---

# 3. Installation

### ✅ Installing globally

```sh
npm install -g solavia
```

or, if you're developing locally:

```sh
npm install
chmod +x solavia.js
```

Then you can run:

```sh
./solavia.js help
```

---

# 4. Writing a Pipeline Script

Create: `pipelines/example.js`

```js
export default async function (sv) {
  sv.stage("Init", () => {
    return { hello: "world", timestamp: Date.now() };
  });

  sv.stage("Compute", (prev) => {
    return prev.hello + " / deterministic result";
  });
}
```

Each `sv.stage()` automatically:

* hashes stage input (`sha256Hex`)
* hashes stage output
* records metadata into the Merkle provenance chain

---

# 5. Running a Pipeline

```
solavia run pipelines/example.js
```

Output:

```
Info  Running pipeline: example.js
Info  Seed: 1337
Success Pipeline completed in 4ms
Success Merkle Root: 5ab1c6a1...
```

---

# 6. Export Merkle Proof

```
solavia run pipelines/example.js --prove
```

Generated file:

```
solavia-proof.json
```

Example structure:

```json
{
  "root": "a4bdf...",
  "seed": 1337,
  "timestamp": "2025-10-28T04:33:21.314Z",
  "version": "8.0.0",
  "stages": [
    {
      "name": "Init",
      "inputHash": "823fac...",
      "outputHash": "c0a81b...",
      "ts": 1730098612314
    }
  ]
}
```

This proves that:

* stage outputs were produced by this pipeline
* they match the Merkle root

---

# 7. Export Merkle Proof **and sign it**

### (Requires a private key, PEM format)

```sh
solavia run pipelines/example.js --prove --sign=my.pem
```

Produces two outputs:

```
solavia-proof.json
solavia-signature.json
```

`solavia-signature.json` contains:

```json
{
  "root": "a4bdf...",
  "signature": "4f92d8ca..."
}
```

---

# 8. Verify Proof (optional signature)

### ✅ Verify Merkle only

```sh
solavia verify solavia-proof.json
```

### ✅ Verify Merkle + signature

```sh
solavia verify solavia-proof.json --signature solavia-signature.json --pubkey pub.pem
```

Output:

```
Success Signature valid
```

---

# 9. Snapshots & Rollbacks

Solavia includes versioned state persistence.

### Create a snapshot:

```sh
solavia snapshot "after-v1"
```

Output:

```
Success Snapshot saved: bafyreiabcd... (after-v1)
```

### Rollback from snapshot:

```sh
solavia rollback bafyreiabcd...
```

---

# 10. CLI Reference (Full)

```
solavia <command> [options]

Commands:
  run <file.js>     Run a pipeline script
  verify [proof]    Verify Merkle proof + signature
  snapshot [name]   Create named snapshot
  rollback <cid>    Restore from snapshot
  help              Show this help

Run Options:
  --seed=1337       Deterministic execution seed
  --prove=file.json Export Merkle proof
  --sign=key.pem    Sign proof using private key (PEM)
  --signature=file  Output signature file
  --pubkey=file     Public key for signature verification
  --storage=ipfs    Use Helia/IPFS (default: local)
```

---

# 11. Internal Architecture (High-Level Explanation)

| Layer                              | Responsibility                            |
| ---------------------------------- | ----------------------------------------- |
| CLI / Commands                     | Runs pipeline, verify, snapshot, rollback |
| Provenance Engine (`solavia-core`) | Builds Merkle tree of stage outputs       |
| Crypto                             | SHA256 hashing, signature verification    |
| Storage Adapter                    | Local OR IPFS (Helia), pluggable          |

Merkle Tree Contract:

```
root = Merkle( stage1Hash, stage2Hash, stage3Hash, ... )
```

Any single tampered stage invalidates the final Merkle root.

---

# 12. Security & Determinism Guarantees

| Guarantee               | Meaning                                               |
| ----------------------- | ----------------------------------------------------- |
| Deterministic execution | `seed` ensures identical pipeline results across runs |
| Verifiable outputs      | Every stage hashed & included in Merkle tree          |
| Anti tamper             | If ANY leaf changes, Merkle root is invalid           |
| Audit trail             | User can prove exact sequence of operations occurred  |
| Optional signature      | Non-repudiable proof tied to identity / private key   |

--
