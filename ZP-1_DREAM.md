I would design a **third algorithm**: **ZP-1 — ZEUZ/PITHOS Envelope v1**.

It would keep the best part of **ZEUZ**: the formal, theorem-shaped construction with explicit assumptions, canonical parsing, commitments, Merkle binding, and reduction-style security targets.

It would keep the best part of **PITHOS-1**: a concrete, readable, implementable primitive suite.

But I would not ship either one exactly as shown. I would ship a cleaner hybrid envelope.

## ZP-1: the algorithm I would want implemented

**Purpose:** long-term, post-quantum, signed public-key encryption for files, software artifacts, backups, credentials, model weights, source archives, and sealed messages.

It is a **KEM/KDF/AEAD envelope**, similar in spirit to HPKE, but with stronger file/object semantics: chunking, Merkle integrity, signer binding, recipient binding, key commitment, canonical encoding, and a signed manifest. HPKE itself standardizes the KEM/KDF/AEAD hybrid-encryption pattern for arbitrary-sized plaintexts; ZP-1 would use that pattern but add a durable signed object format. ([RFC Editor][1])

## Primitive suite

My default suite would be:

```text
KEM        = ML-KEM-1024
Signature  = ML-DSA-87
Archive signature, optional but preferred for long-lived artifacts
           = SLH-DSA level-5 profile
Hash       = SHA-384
KDF        = Extract-then-expand using HMAC-SHA-384
AEAD       = AES-256-GCM-SIV
Encoding   = one canonical binary encoding only
Chunks     = fixed-size authenticated chunks
Tree       = domain-separated SHA-384 Merkle tree
Failure    = one generic authentication failure
```

ML-KEM is the NIST-standardized module-lattice KEM, with ML-KEM-512, ML-KEM-768, and ML-KEM-1024 as its increasing-strength parameter sets. ([NIST Computer Security Resource Center][2]) ML-DSA is NIST’s module-lattice digital-signature standard. ([NIST Computer Security Resource Center][3]) For long-term archival signatures, I would add an SLH-DSA co-signature because NIST standardized SLH-DSA as a stateless hash-based signature scheme. ([NIST Computer Security Resource Center][4])

I would choose **AES-256-GCM-SIV** over plain AES-GCM for the default profile because it is nonce-misuse resistant; repeated nonces are still bad, but they are not the catastrophic failure mode they are in ordinary GCM. RFC 8452 specifies AES-GCM-SIV as nonce-misuse-resistant authenticated encryption. ([IETF Datatracker][5]) A strict FIPS-only profile could use AES-256-GCM, since NIST SP 800-38D specifies GCM/GMAC, but I would personally prefer GCM-SIV for future infrastructure when compliance constraints allow it. ([NIST Computer Security Resource Center][6])

## High-level object format

```text
ZP1_Object =
    BaseHeader
    RecipientStanza[1..m]
    PublicManifest
    ChunkCiphertext[0..n-1]
    ManifestTag
    SignatureBlock
```

The important design choice is that ZP-1 separates the **content secret** from the **recipient KEM result**.

Each file gets a fresh random `content_secret`. The content is encrypted once. Then the content secret is wrapped separately for each recipient using ML-KEM. That allows multi-recipient encryption, future recipient rotation, and object rewrapping without re-encrypting the entire file.

## Seal

```text
Seal(pk_R[1..m], sk_S, pk_S, AAD, P):

1. Validate every recipient public key and signer public key.
   Reject non-canonical encodings.

2. Generate:
      content_secret ← random 384-bit value
      object_id      ← random 128-bit value
      chunk_size     ← fixed profile value, e.g. 1 MiB
      n              ← max(1, ceil(len(P) / chunk_size))

3. Build BaseHeader:

      BaseHeader = EncodeCanonical({
          magic: "ZP1",
          version: 1,
          suite: "ML-KEM-1024 / ML-DSA-87 / SHA-384 / HMAC-SHA384 / AES-256-GCM-SIV",
          object_id,
          chunk_size,
          plaintext_length: len(P),
          aad_hash: SHA384("aad" || AAD),
          signer_pk_hash: SHA384("signer-pk" || EncodeCanonical(pk_S)),
          flags,
          limits
      })

4. For each recipient j:

      (ct_kem_j, ss_j) = ML-KEM-1024.Encaps(pk_R[j])

      recipient_header_j = EncodeCanonical({
          recipient_index: j,
          recipient_pk_hash: SHA384("recipient-pk" || EncodeCanonical(pk_R[j])),
          kem_ciphertext: ct_kem_j
      })

      wrap_salt_j = SHA384(
          "ZP1 recipient wrap salt" ||
          BaseHeader ||
          recipient_header_j
      )

      PRK_wrap_j = HMAC-SHA384(
          key  = wrap_salt_j,
          data = ss_j
      )

      K_wrap_j = Expand(
          PRK_wrap_j,
          label = "ZP1 wrap key",
          info  = BaseHeader || recipient_header_j,
          len   = 32
      )

      wrapped_content_secret_j =
          AES-256-GCM-SIV.Seal(
              key   = K_wrap_j,
              nonce = 0^96,
              pt    = content_secret,
              aad   = BaseHeader || recipient_header_j
          )

      RecipientStanza[j] = EncodeCanonical({
          recipient_header_j,
          wrapped_content_secret_j
      })

5. Derive content keys:

      stanzas_hash = SHA384("recipient-stanzas" || RecipientStanza[1] || ... || RecipientStanza[m])

      content_salt = SHA384(
          "ZP1 content salt" ||
          BaseHeader ||
          stanzas_hash ||
          SHA384("aad" || AAD)
      )

      PRK_content = HMAC-SHA384(
          key  = content_salt,
          data = content_secret
      )

      K_aead     = Expand(PRK_content, "ZP1 chunk AEAD key",      BaseHeader || stanzas_hash, 32)
      K_commit   = Expand(PRK_content, "ZP1 key commitment key",  BaseHeader || stanzas_hash, 32)
      K_manifest = Expand(PRK_content, "ZP1 manifest MAC key",    BaseHeader || stanzas_hash, 32)

6. Compute key commitment:

      key_commitment = HMAC-SHA384(
          K_commit,
          "ZP1 content key commitment" ||
          BaseHeader ||
          stanzas_hash ||
          SHA384("aad" || AAD)
      )

7. Encrypt chunks:

      For i = 0 .. n-1:

          P_i = chunk i of P

          nonce_i = uint32_be(0) || uint64_be(i)

          chunk_aad_i = EncodeCanonical({
              domain: "ZP1 chunk aad",
              base_header_hash: SHA384(BaseHeader),
              stanzas_hash,
              key_commitment,
              aad_hash: SHA384("aad" || AAD),
              index: i,
              chunk_count: n,
              plaintext_length: len(P),
              chunk_length: len(P_i)
          })

          C_i = AES-256-GCM-SIV.Seal(
              key   = K_aead,
              nonce = nonce_i,
              pt    = P_i,
              aad   = chunk_aad_i
          )

          L_i = SHA384(
              "ZP1 merkle leaf" ||
              uint64_be(i) ||
              uint64_be(len(P_i)) ||
              nonce_i ||
              C_i ||
              SHA384(chunk_aad_i)
          )

8. Compute Merkle root:

      root = MerkleRoot_SHA384(
          leaves = L_0, ..., L_{n-1},
          leaf_domain = "ZP1 merkle leaf",
          node_domain = "ZP1 merkle node"
      )

9. Build PublicManifest:

      PublicManifest = EncodeCanonical({
          base_header_hash: SHA384(BaseHeader),
          stanzas_hash,
          key_commitment,
          chunk_count: n,
          chunk_size,
          plaintext_length: len(P),
          merkle_root: root,
          aad_hash: SHA384("aad" || AAD),
          signer_pk_hash: SHA384("signer-pk" || EncodeCanonical(pk_S))
      })

10. Compute manifest tag:

      ManifestTag = HMAC-SHA384(
          K_manifest,
          "ZP1 manifest tag" || PublicManifest
      )

11. Sign the public transcript:

      sig_input = SHA384(
          "ZP1 signature input" ||
          BaseHeader ||
          RecipientStanza[1] || ... || RecipientStanza[m] ||
          PublicManifest ||
          ManifestTag
      )

      sigma_mldsa = ML-DSA-87.Sign(sk_S, sig_input)

      Optional archive mode:
          sigma_slh = SLH-DSA.Sign(sk_S_archive, sig_input)

12. Output:

      ZP1_Object =
          BaseHeader ||
          RecipientStanza[1..m] ||
          PublicManifest ||
          C_0 || ... || C_{n-1} ||
          ManifestTag ||
          SignatureBlock
```

## Open

```text
Open(sk_R, pk_S, AAD, ZP1_Object):

1. Canonically parse the object.
   Reject duplicate fields, non-canonical encodings, unknown critical flags,
   invalid lengths, impossible chunk counts, and unsupported suites.

2. Check:

      SHA384("aad" || AAD) matches the aad_hash in BaseHeader and PublicManifest.

3. Recompute the ciphertext Merkle root from C_0 ... C_{n-1}.
   Reject if it does not match PublicManifest.merkle_root.

4. Verify the signature block before releasing plaintext:

      sig_input = SHA384(
          "ZP1 signature input" ||
          BaseHeader ||
          RecipientStanza[1] || ... || RecipientStanza[m] ||
          PublicManifest ||
          ManifestTag
      )

      require ML-DSA-87.Verify(pk_S, sigma_mldsa, sig_input) = true

      In archive mode:
          require SLH-DSA.Verify(pk_S_archive, sigma_slh, sig_input) = true

5. Locate the recipient stanza whose recipient_pk_hash matches sk_R’s public key.

6. Decapsulate:

      ss_j = ML-KEM-1024.Decaps(sk_R, ct_kem_j)

7. Derive K_wrap_j exactly as in Seal.

8. Unwrap content_secret:

      content_secret =
          AES-256-GCM-SIV.Open(
              key   = K_wrap_j,
              nonce = 0^96,
              ct    = wrapped_content_secret_j,
              aad   = BaseHeader || recipient_header_j
          )

      If unwrap fails, return ZP1_ERR_AUTH.

9. Derive K_aead, K_commit, and K_manifest.

10. Recompute key_commitment.
    Require exact equality with PublicManifest.key_commitment.

11. Recompute ManifestTag.
    Require exact equality.

12. Decrypt chunks:

      For i = 0 .. n-1:
          recompute chunk_aad_i
          P_i = AES-256-GCM-SIV.Open(K_aead, nonce_i, C_i, chunk_aad_i)
          if any chunk fails, return ZP1_ERR_AUTH

13. Output:

      P = P_0 || ... || P_{n-1}
```

All failure paths return exactly:

```text
ZP1_ERR_AUTH
```

No separate “bad signature,” “bad recipient,” “bad padding,” “bad tag,” “wrong AAD,” or “bad key” errors.

## What this improves over both images

Compared with **PITHOS-1**, ZP-1 adds:

```text
multi-recipient support
content-secret wrapping
signed public manifest
explicit key commitment
manifest MAC
Merkle-root binding
optional hash-based archival co-signature
nonce-misuse-resistant AEAD default
strict canonical parse rules
no plaintext release before full verification
one uniform failure symbol
```

Compared with **ZEUZ**, ZP-1 adds:

```text
a concrete primitive suite
an implementable object format
recipient stanzas
exact Seal/Open flow
specific KDF labels
specific signature transcript
specific chunk AAD
specific operational limits
```

## Security target

The theorem I would want attached to ZP-1 is:

```text
Assumptions_ZP1 =
    ML-KEM-1024 is IND-CCA secure
 ∧  HMAC-SHA384 KDF is a PRF/extractor for this use
 ∧  AES-256-GCM-SIV is AEAD-secure under the profile limits
 ∧  ML-DSA-87 is EUF-CMA secure
 ∧  optional SLH-DSA archive signature is EUF-CMA secure
 ∧  SHA-384 is collision resistant
 ∧  canonical encoding is injective
 ∧  all keys are validated and suite identifiers are fixed

Then ZP1 provides:

    recipient confidentiality
 ∧  ciphertext integrity
 ∧  signer authenticity
 ∧  AAD binding
 ∧  recipient-key binding
 ∧  signer-key binding
 ∧  chunk order/length integrity
 ∧  key commitment
 ∧  downgrade resistance
 ∧  splice resistance
```

## The design choice I care about most

The most important difference from both originals is this:

> **The signature signs the manifest, the manifest binds the Merkle root, the Merkle root binds every ciphertext chunk, the chunk AAD binds the header/AAD/key commitment, and the key commitment binds the content secret.**

That makes the object hard to splice, downgrade, reorder, partially replay, cross-protocol reuse, or misattribute.

## My final pick

I would not choose raw ZEUZ or raw PITHOS-1.

I would implement:

```text
ZP-1 Core:
    ML-KEM-1024
    ML-DSA-87
    SHA-384
    HMAC-SHA384 KDF
    AES-256-GCM-SIV
    Merkle manifest
    key commitment
    canonical encoding

ZP-1 Archive:
    everything in Core
    plus required SLH-DSA co-signature
```

For my technological future, I would want **ZP-1 Core** everywhere ordinary encrypted objects are used, and **ZP-1 Archive** for software updates, legal records, root keys, firmware, backups, scientific datasets, model releases, and anything expected to survive for decades.

[1]: https://www.rfc-editor.org/info/rfc9180/?utm_source=chatgpt.com "RFC 9180: Hybrid Public Key Encryption"
[2]: https://csrc.nist.gov/pubs/fips/203/final?utm_source=chatgpt.com "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
[3]: https://csrc.nist.gov/pubs/fips/204/final?utm_source=chatgpt.com "FIPS 204, Module-Lattice-Based Digital Signature Standard"
[4]: https://csrc.nist.gov/pubs/fips/205/final?utm_source=chatgpt.com "FIPS 205, Stateless Hash-Based Digital Signature Standard"
[5]: https://datatracker.ietf.org/doc/html/rfc8452?utm_source=chatgpt.com "RFC 8452 - AES-GCM-SIV: Nonce Misuse-Resistant ..."
[6]: https://csrc.nist.gov/pubs/sp/800/38/d/final?utm_source=chatgpt.com "Recommendation for Block Cipher Modes of Operation: Galois ..."
