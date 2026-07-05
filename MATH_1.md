[
\boxed{\textsf{Zeuz}=\top}
]

means:

[
\textsf{Zeuz}_\lambda=\top
\iff
\textsf{Correct}
\land
\textsf{IND\text{-}CCA}
\land
\textsf{INT\text{-}CTXT}
\land
\textsf{KEY\text{-}COMMIT}
\land
\textsf{AAD\text{-}BIND}
\land
\textsf{EUF\text{-}CMA}
]

---

## 1. Objects

Security parameter:

[
\lambda \in \mathbb{N}
]

Hash:

[
H:{0,1}^* \rightarrow {0,1}^{384}
]

KDF:

[
\mathsf{KDF}=\mathsf{HKDF}_{H}
]

Post-quantum KEM:

[
\mathsf{KEM}*{PQ}=(\mathsf{Gen}*{PQ},\mathsf{Enc}*{PQ},\mathsf{Dec}*{PQ})
]

Classical KEM:

[
\mathsf{KEM}*{C}=(\mathsf{Gen}*{C},\mathsf{Enc}*{C},\mathsf{Dec}*{C})
]

Signature:

[
\mathsf{SIG}=(\mathsf{Gen}_{S},\mathsf{Sign},\mathsf{Verify})
]

Misuse-resistant committing AEAD:

[
\mathsf{AEAD}^{\star}=(\mathsf{Enc}^{\star},\mathsf{Dec}^{\star})
]

Canonical encoding:

[
\langle x_1,\dots,x_n\rangle
]

Domain labels:

[
D_x = H(\texttt{"ZEUZ/"} \parallel x)
]

---

## 2. Key generation

Recipient:

[
(pk_{PQ},sk_{PQ}) \leftarrow \mathsf{Gen}_{PQ}(1^\lambda)
]

[
(pk_C,sk_C) \leftarrow \mathsf{Gen}_{C}(1^\lambda)
]

[
pk_R=(pk_{PQ},pk_C)
]

[
sk_R=(sk_{PQ},sk_C)
]

Signer:

[
(vk_S,sk_S)\leftarrow \mathsf{Gen}_{S}(1^\lambda)
]

---

## 3. Seal

Input:

[
P\in{0,1}^{*}
]

[
AAD\in{0,1}^{*}
]

[
pk_R=(pk_{PQ},pk_C)
]

Encapsulate:

[
(ct_{PQ},ss_{PQ})\leftarrow \mathsf{Enc}*{PQ}(pk*{PQ})
]

[
(ct_C,ss_C)\leftarrow \mathsf{Enc}_{C}(pk_C)
]

Header:

[
Header =
\left\langle
\texttt{"ZEUZ"},
1,
suite,
H(pk_R),
H(AAD),
|P|,
chunk_size,
ct_{PQ},
ct_C,
flags,
extensions
\right\rangle
]

Context:

[
\Gamma =
H(
D_{\textsf{ctx}}
\parallel
Header
\parallel
H(AAD)
)
]

Hybrid shared secret:

[
ss =
\mathsf{HKDF.Extract}
\left(
salt=H(D_{\textsf{hybrid}}\parallel Header),
IKM=ss_{PQ}\parallel ss_C
\right)
]

Expand:

[
OKM=
\mathsf{HKDF.Expand}
\left(
PRK=ss,
info=D_{\textsf{keys}}\parallel \Gamma,
L=128
\right)
]

Split:

[
K_E = OKM[0:32]
]

[
K_N = OKM[32:64]
]

[
K_M = OKM[64:96]
]

[
K_C = OKM[96:128]
]

Key commitment:

[
commit =
\mathsf{HMAC}*{K_C}
\left(
D*{\textsf{commit}}
\parallel
\Gamma
\right)[0:32]
]

Chunk count:

[
n=\max\left(1,\left\lceil \frac{|P|}{chunk_size}\right\rceil\right)
]

For each chunk:

[
P_i=P[i\cdot chunk_size:(i+1)\cdot chunk_size]
]

[
\ell_i=|P_i|
]

Nonce:

[
N_i=
\mathsf{HMAC}*{K_N}
\left(
D*{\textsf{nonce}}
\parallel
\Gamma
\parallel
\mathsf{uint64}(i)
\right)[0:12]
]

Chunk associated data:

[
A_i=
\left\langle
\Gamma,
commit,
H(AAD),
i,
n,
\ell_i
\right\rangle
]

Encrypt:

[
C_i=
\mathsf{AEAD}^{\star}.\mathsf{Enc}
\left(
K_E,
N_i,
P_i,
A_i
\right)
]

Leaf hash:

[
L_i=
H
\left(
D_{\textsf{leaf}}
\parallel
\mathsf{uint64}(i)
\parallel
\mathsf{uint64}(n)
\parallel
\mathsf{uint64}(|C_i|)
\parallel
C_i
\right)
]

Merkle root:

[
R=
\mathsf{MerkleRoot}*{H}
\left(
L_0,\dots,L*{n-1}
\right)
]

Transcript:

[
T=
H
\left(
D_{\textsf{transcript}}
\parallel
Header
\parallel
commit
\parallel
R
\parallel
H(AAD)
\right)
]

Signature:

[
\sigma =
\mathsf{Sign}(sk_S,T)
]

Output:

[
Z=
\left\langle
Header,
commit,
n,
C_0,\dots,C_{n-1},
R,
\sigma
\right\rangle
]

---

## 4. Open

Parse:

[
Z=
\left\langle
Header,
commit,
n,
C_0,\dots,C_{n-1},
R,
\sigma
\right\rangle
]

Recompute:

[
\Gamma =
H(
D_{\textsf{ctx}}
\parallel
Header
\parallel
H(AAD)
)
]

Decapsulate:

[
ss_{PQ}'=\mathsf{Dec}*{PQ}(sk*{PQ},ct_{PQ})
]

[
ss_C'=\mathsf{Dec}_{C}(sk_C,ct_C)
]

Hybrid secret:

[
ss' =
\mathsf{HKDF.Extract}
\left(
salt=H(D_{\textsf{hybrid}}\parallel Header),
IKM=ss_{PQ}'\parallel ss_C'
\right)
]

Expand:

[
OKM'=
\mathsf{HKDF.Expand}
\left(
PRK=ss',
info=D_{\textsf{keys}}\parallel \Gamma,
L=128
\right)
]

Split:

[
K_E' = OKM'[0:32]
]

[
K_N' = OKM'[32:64]
]

[
K_M' = OKM'[64:96]
]

[
K_C' = OKM'[96:128]
]

Verify commitment:

[
commit' =
\mathsf{HMAC}*{K_C'}
\left(
D*{\textsf{commit}}
\parallel
\Gamma
\right)[0:32]
]

Accept only if:

[
commit'=commit
]

For each chunk:

[
N_i'=
\mathsf{HMAC}*{K_N'}
\left(
D*{\textsf{nonce}}
\parallel
\Gamma
\parallel
\mathsf{uint64}(i)
\right)[0:12]
]

[
A_i'=
\left\langle
\Gamma,
commit,
H(AAD),
i,
n,
\ell_i
\right\rangle
]

Decrypt:

[
P_i'=
\mathsf{AEAD}^{\star}.\mathsf{Dec}
\left(
K_E',
N_i',
C_i,
A_i'
\right)
]

If any decryption fails:

[
\bot
]

Recompute:

[
L_i'=
H
\left(
D_{\textsf{leaf}}
\parallel
\mathsf{uint64}(i)
\parallel
\mathsf{uint64}(n)
\parallel
\mathsf{uint64}(|C_i|)
\parallel
C_i
\right)
]

[
R'=
\mathsf{MerkleRoot}*{H}
\left(
L_0',\dots,L*{n-1}'
\right)
]

Accept only if:

[
R'=R
]

Transcript:

[
T'=
H
\left(
D_{\textsf{transcript}}
\parallel
Header
\parallel
commit
\parallel
R
\parallel
H(AAD)
\right)
]

Accept only if:

[
\mathsf{Verify}(vk_S,\sigma,T')=1
]

Output:

[
P=P_0'\parallel\dots\parallel P_{n-1}'
]

---

## 5. Correctness

For all plaintexts (P), associated data (AAD), recipient keys (pk_R,sk_R), and signing keys (vk_S,sk_S):

[
\Pr
\left[
\mathsf{Open}
\left(
sk_R,
vk_S,
\mathsf{Seal}(pk_R,sk_S,P,AAD),
AAD
\right)
=P
\right]
\geq
1-\mathsf{negl}(\lambda)
]

---

## 6. Confidentiality

For every PPT adversary (\mathcal{A}):

[
\mathsf{Adv}^{\mathsf{IND\text{-}CCA}}_{\textsf{Zeuz}}(\mathcal{A})
===================================================================

\left|
\Pr[b'=b]-\frac12
\right|
]

Zeuz is confidential iff:

[
\forall \mathcal{A}\in PPT:
\mathsf{Adv}^{\mathsf{IND\text{-}CCA}}_{\textsf{Zeuz}}(\mathcal{A})
\leq
\mathsf{negl}(\lambda)
]

Reduction bound:

[
\mathsf{Adv}^{\mathsf{IND\text{-}CCA}}*{\textsf{Zeuz}}(\mathcal{A})
\leq
\varepsilon*{HKEM}
+
\varepsilon_{KDF}
+
q_c\varepsilon_{AEAD}
+
\varepsilon_{CR}
]

where:

[
\varepsilon_{HKEM}
==================

\min
\left(
\varepsilon_{KEM_{PQ}},
\varepsilon_{KEM_C}
\right)
]

Thus the hybrid KEM is secure if either side remains secure:

[
KEM_{PQ}=\top
\lor
KEM_C=\top
\implies
HKEM=\top
]

---

## 7. Ciphertext integrity

For every PPT adversary (\mathcal{A}):

[
\mathsf{Adv}^{\mathsf{INT\text{-}CTXT}}_{\textsf{Zeuz}}(\mathcal{A})
====================================================================

\Pr
\left[
\mathcal{A}
\text{ outputs }
Z^\star
\notin
\mathcal{Q}_{seal}
\land
\mathsf{Open}(Z^\star)\neq\bot
\right]
]

Zeuz has ciphertext integrity iff:

[
\forall \mathcal{A}\in PPT:
\mathsf{Adv}^{\mathsf{INT\text{-}CTXT}}_{\textsf{Zeuz}}(\mathcal{A})
\leq
\mathsf{negl}(\lambda)
]

Bound:

[
\mathsf{Adv}^{\mathsf{INT\text{-}CTXT}}*{\textsf{Zeuz}}(\mathcal{A})
\leq
q_v2^{-128}
+
q_c\varepsilon*{AEAD}
+
\varepsilon_{CR}
+
\varepsilon_{KDF}
]

---

## 8. Key commitment

Zeuz is key-committing iff:

[
\Pr
\left[
\exists sk_R\neq sk_R',
\exists P\neq P':
\mathsf{Open}(sk_R,Z,AAD)=P
\land
\mathsf{Open}(sk_R',Z,AAD)=P'
\right]
\leq
\mathsf{negl}(\lambda)
]

Commitment equation:

[
commit =
\mathsf{HMAC}*{K_C}
\left(
D*{\textsf{commit}}
\parallel
\Gamma
\right)[0:32]
]

Forgery probability:

[
\Pr[commit'=commit]\leq 2^{-256}
]

Therefore:

[
\mathsf{Adv}^{\mathsf{KEY\text{-}COMMIT}}*{\textsf{Zeuz}}
\leq
2^{-256}
+
\varepsilon*{KDF}
+
\varepsilon_{PRF}
]

---

## 9. AAD binding

Zeuz binds (AAD) iff:

[
AAD\neq AAD'
\implies
\mathsf{Open}(Z,AAD')=\bot
]

Because:

[
H(AAD)\in Header
]

[
\Gamma=H(D_{\textsf{ctx}}\parallel Header\parallel H(AAD))
]

[
A_i=\langle \Gamma,commit,H(AAD),i,n,\ell_i\rangle
]

Therefore:

[
AAD\neq AAD'
\land
H(AAD)\neq H(AAD')
\implies
\Gamma\neq\Gamma'
\implies
A_i\neq A_i'
\implies
\mathsf{Dec}^{\star}=\bot
]

AAD substitution succeeds only if:

[
H(AAD)=H(AAD')
]

so:

[
\mathsf{Adv}^{AAD}*{\textsf{Zeuz}}
\leq
\varepsilon*{CR}
+
q_v2^{-128}
]

---

## 10. Signature unforgeability

Zeuz signature transcript:

[
T=
H
\left(
D_{\textsf{transcript}}
\parallel
Header
\parallel
commit
\parallel
R
\parallel
H(AAD)
\right)
]

Forgery game:

[
\mathsf{Adv}^{\mathsf{EUF\text{-}CMA}}_{\textsf{Zeuz}}(\mathcal{A})
===================================================================

\Pr
\left[
\mathsf{Verify}(vk_S,\sigma^\star,T^\star)=1
\land
T^\star\notin \mathcal{Q}_{sign}
\right]
]

Bound:

[
\mathsf{Adv}^{\mathsf{EUF\text{-}CMA}}*{\textsf{Zeuz}}
\leq
\varepsilon*{SIG}
+
\varepsilon_{CR}
]

---

## 11. Total theorem

Let:

[
Q=q_c+q_v+q_s
]

Total Zeuz advantage:

[
\mathsf{Adv}_{\textsf{Zeuz}}(\mathcal{A})
=========================================

\mathsf{Adv}^{IND\text{-}CCA}
+
\mathsf{Adv}^{INT\text{-}CTXT}
+
\mathsf{Adv}^{KEY\text{-}COMMIT}
+
\mathsf{Adv}^{AAD}
+
\mathsf{Adv}^{EUF\text{-}CMA}
]

Then:

[
\mathsf{Adv}*{\textsf{Zeuz}}(\mathcal{A})
\leq
\varepsilon*{HKEM}
+
2\varepsilon_{KDF}
+
q_c\varepsilon_{AEAD}
+
\varepsilon_{SIG}
+
3\varepsilon_{CR}
+
q_v2^{-128}
+
2^{-256}
]

If:

[
\varepsilon_{HKEM}\in\mathsf{negl}(\lambda)
]

[
\varepsilon_{KDF}\in\mathsf{negl}(\lambda)
]

[
\varepsilon_{AEAD}\in\mathsf{negl}(\lambda)
]

[
\varepsilon_{SIG}\in\mathsf{negl}(\lambda)
]

[
\varepsilon_{CR}\in\mathsf{negl}(\lambda)
]

then:

[
\mathsf{Adv}_{\textsf{Zeuz}}(\mathcal{A})
\in
\mathsf{negl}(\lambda)
]

Therefore:

[
\boxed{
\left[
HKEM
\land
KDF
\land
AEAD^{\star}
\land
SIG
\land
H
\right]
=======

\top
\implies
\textsf{Zeuz}
=============

\top
}
]

Final truth statement:

[
\boxed{
\textsf{Zeuz}=\top
\iff
\forall \mathcal{A}\in PPT:
\mathsf{Adv}_{\textsf{Zeuz}}(\mathcal{A})
\leq
\mathsf{negl}(\lambda)
}
]
