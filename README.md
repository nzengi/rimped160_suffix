# Pre-Suffix Filtering for RIPEMD-160 Hash Search Space Reduction

In this table, we describe the key mathematical formulas and how they reduce the search space for private key discovery, focusing on the **prefix** and **suffix** of the **RIPEMD-160** hash.

| **Concept**                        | **Description**                                                                 | **Math**                                                                 |
|------------------------------------|---------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| **Elliptic Curve Multiplication**  | The public key \( P \) is derived from the private key \( k \) using elliptic curve multiplication. | $$ P = k \cdot G $$                                                          |
| **Public Key Hashing**             | The public key \( P \) is hashed using **SHA-256**, followed by **RIPEMD-160** to get the public key hash \( H_{PKH} \). | $$ H_{PKH} = \text{RIPEMD-160}(\text{SHA-256}(P)) $$                                    |
| **Prefix-Suffix Filtering**        | The search space is reduced by knowing the prefix \( H_p \) and suffix \( H_s \) of the hash. | $$ H_{PKH} = H_p \ || \ H_{\text{middle}} \ || \ H_s $$                            |
| **Reduced Search Space**           | Knowing the prefix and suffix reduces the effective search space to \( 2^{160 - (n_p + n_s)} \). | $$ S = 2^{160 - (n_p + n_s)} $$                                                 |
| **Example: 16-bit Prefix and Suffix** | If the prefix and suffix are both 16 bits, the search space becomes \( 2^{128} \), significantly reducing the effort required. | $$ S = 2^{160 - (16 + 16)} = 2^{128} $$        |
| **Pre-Suffix Filter Application**  | This method is applied by checking if the computed public key hash starts with the target prefix and ends with the target suffix. | $$ \text{if} \ (H_{PKH}[0:4] == H_p) \ \text{and} \ (H_{PKH}[-4:] == H_s): $$            |

### Explanation of Table Entries:

1. **Elliptic Curve Multiplication**: This formula describes how the public key \( P \) is computed from a private key \( k \), using elliptic curve multiplication on the SECP256k1 curve.
   
2. **Public Key Hashing**: Once the public key \( P \) is generated, it is hashed using **SHA-256** followed by **RIPEMD-160** to generate the public key hash \( H_{PKH} \).

3. **Prefix-Suffix Filtering**: The core of the pre-suffix method is that if an attacker knows the first few (prefix) and last few (suffix) bits of the RIPEMD-160 hash, the search space is significantly reduced by focusing only on the middle portion of the hash.

4. **Reduced Search Space**: The formula shows how the search space decreases. Instead of searching the entire 160-bit hash space, the knowledge of prefix \( H_p \) and suffix \( H_s \) reduces it by the number of known bits.

5. **Example**: In practice, if 16 bits are known for both the prefix and suffix, the search space is reduced to \( 2^{128} \), which is much smaller than the full \( 2^{160} \) space.

6. **Pre-Suffix Filter Application**: This shows how the method can be implemented algorithmically by checking if the calculated public key hash matches the known prefix and suffix.

