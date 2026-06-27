# CTF Affine GF(2) Cipher Solver

A solver for a CTF challenge recovering plaintexts from a vulnerable affine block cipher by exploiting its accidental affine structure over **GF(2)**.

This repository contains the exploit script used in the writeup:

> **Cryptanalysis: Recovering an Affine Encryption Scheme Using GF(2) Linear Algebra**

The challenge cipher appears secure at first glance because it uses:

* Key-dependent S-Boxes
* Bit permutations
* 100 rounds of encryption
* A custom hash construction

However, every component is either **linear** or **affine** over GF(2), causing the entire cipher to collapse into a single affine transformation:

```math
E(x) = Mx \oplus c
```

The solver reconstructs this transformation and recovers the original plaintext by solving a system of linear equations over GF(2).

---

## Features

* Verifies whether the S-Box is affine.
* Reconstructs the complete `256 × 256` affine matrix.
* Recovers the affine constant vector.
* Uses Gaussian elimination over GF(2).
* Recovers plaintext without brute force.

---

## Usage

```bash
python3 solver.py
```

Target digest:

```text
1d6a2172025e1858754075123b6658532d1a4e775e1f43336e227d5a4529734f
```

---

## Attack Overview

1. Verify the S-Box satisfies:

```text
S(a ⊕ b) = S(a) ⊕ S(b) ⊕ S(0)
```

2. Recover the affine constant:

```text
c = E(0)
```

3. Encrypt all basis vectors to reconstruct matrix `M`.

4. Solve:

```text
Mx = y ⊕ c
```

using Gaussian elimination over GF(2).

5. Recover the original plaintext.

---

## Full Technical Writeup

For a complete explanation of the vulnerability, mathematical background, and attack methodology, read the full writeup:

### [Cryptanalysis: Recovering an Affine Encryption Scheme Using GF(2) Linear Algebra](https://apt2002.medium.com)

---

## Disclaimer

This repository is provided for educational and research purposes only. It demonstrates how seemingly complex cryptographic constructions can fail when nonlinearity is absent.

Always use standardized and peer reviewed cryptographic primitives in production systems.

---

<p align="center">
  If you found this project useful, consider starring the repository.
</p>

