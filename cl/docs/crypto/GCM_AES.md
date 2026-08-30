# Summary
1. [Understanding of GCM](#understanding-of-gcm)
   - [Overall](#overall)
   - [GHASH](#ghash)
   - [Counter Block](#counter-block)
   - [Tag](#tag)
   - [Bit-reflection convention](#bit-reflection-convention)
2. [Implementation](#implementation)
   - [Key setup & H-powers precomputation](#key-setup--h-powers-precomputation)
   - [gf_multiply_clmul](#gf_multiply_clmul)
     - [Karatsuba](#karatsuba)
     - [×x offset](#x-offset)
     - [Reduction](#reduction)
   - [Batched multiplication (gf_multiply_batch4_clmul)](#batched-multiplication)
   - [Main encrypt/decrypt loop](#main-encryptdecrypt-loop)
   - [Nonce processing (96-bit vs arbitrary length)](#nonce-processing)
   - [Tag finalization](#tag-finalization)
3. [Sources](#sources)

<hr/>

## Understanding of GCM
### Overall
GCM is a mode that works around a cipher algorithm/primitive (here it is AES hence GCM_AES). GCM is an AEAD (*Authenticated Encryption with Associated Data*) that work over a CTR mode (see CTR_AES.md for better understanding)
which let you authenticate a message using the GHASH algorithm and an AAD (*Additional Authenticated Data*). Per `NIST SP 800-38D` recommendation, **NEVER** reuse a pair key/nonce. Also there is one things that differ from CTR,
the size in bytes of your PT (*Plaintext*) should be between [0, 2<sup>36</sup> - 32] (extremas includes) as it is the pretty much the only difference with CTR (also you cannot choose the starting value of counter as it is set as
2, but the rest is exactly the same).

### GHASH
GHASH (*Galois hash*) is a hashing algorithm that let the authentication of messages. It works in the Galois field set as GF(2<sup>128</sup>) (just think of it as 128 bits for now), so you only have zeros and ones
(neat on a computer). Because the operations is "carry-less", you can intuitivly use modulo 2 (with decimals calculations) to see what it let you do that :

|              | A = 0 / B = 0 | A = 0 / B = 1 | A = 1 / B = 0 | A = 1 / B = 1 | 
|--------------|---------------|---------------|---------------|---------------|
|Addition      |       0       |       1       |       1       |       0       |
|Substraction  |       0       |       1       |       1       |       0       |
|Multiplication|       0       |       0       |       0       |       1       |

If you have keen eye, you probably have spotted (on my very bad table) that + and - are in fact identical, and that you can replace them with simple **xor**. For the multiplication, it is an **and** operation.
But here you ask, if I were to multiply a 64 bits by 64 bits, is it just an *A and B = C* ? No, it is a little more complicated, but not that much, it is just like we do at hand, we take the first bit apply the **and operation**
and add the result (with a **xor**) in the accumulator (here we do an **and** operation, but us we do integer by integer from right to left for multiplication so it's the same as us on paper in school)
But now we enter the arguably good stuff, the reduction. GF(2<sup>128</sup>) isn't just a 128 bits number, it is a "finite field", what does that mean ? It means that if you were to "overflow" out of that field,
you need a reduction to go back in the field with a "pseudo"-modulo (just think of it as a simple modulo) operation using the polynom (x is a position here) **x<sup>128</sup> = x<sup>7</sup> + x<sup>2</sup> + x + 1**.
<details>
<summary> Proof </summary>

x<sup>128</sup> + x<sup>7</sup> + x<sup>2</sup> + x + 1 = 0 (by construction of the galois field from NIST specifications, just assume it but if you want to know it is an "irreductible polynom" chosen abritrarly)<br/>
<=>  -x<sup>128</sup> = x<sup>7</sup> + x<sup>2</sup> + x + 1<br/>
<=>  x<sup>128</sup> = x<sup>7</sup> + x<sup>2</sup> + x + 1 (yes because we are in the Galois field where - and + are the same)
</details>

So you just do a modulo 1000..(filled with 114 of 0)..00010000111 and bingo you have on paper a GHASH fonction (also you should never have a 1 in the 128 positions as we saw just before). Also yes, 129 bits you saw it right,
there is no issue here.
Also just a quick rectification, it is not a modulo, as "2 non-null element cannot create a null result" so a GF(8) -> Z/8Z doesn't exist with normal integers (0...7) whereas modulo work with it (2x4=0 mod
8 but a finite field doesn't allow it), but for us it doesn't matters (as 0 and 1 is either 0 x 1 but has a null element, or 1 x 1 but the result is 1 so non-null)


### Counter Block
As said before, **NEVER** reuse a pair of key/nonce, never really. Before starting, in NIST documentation there is a clear distinction between the nonce/IV and the counter block (written J with a number behind) as
the counter block is strictly 16 bytes. The first counter block is the *pre-counter block* written **J0**. GCM can accept IV/nonce of a size in [1, 2<sup>61</sup> - 1] (extremas includes) in bytes, but if the nonce
size is equal to 12 bytes (96 bits), that is directly copied to the first bytes in J0, otherwise, you need to use the GHASH algorithm as a way to derive your nonce/IV to get the J0 to get 16 bytes (yes I know not
12 bytes). The recommanded nonce/IV is 12 bytes as it is easier for compatibility across multiple implementation, but for maximum safety, it is better to use 16 bytes nonce/IV (as GHASH is a "linear" function and
has no collision possible (so no reuse possible) except if you H is null) but never go higher than 16 bytes as you loose all protection against collision. Also it is really recommanded (lots of recommandation I know)
to never use nonce/IV of a size lower than 12 bytes (you shouldn't it's dangerous and it may even start to be forbidden in the futur but not as of today). Also never use randomness to fill your nonce, as you probably
know about the birthday paradox (depending on your use case, it may differ, but in general you should have 64 bits of randomness and 32 bits of incrementing for each message)

### Tag
The tag is a 16 bytes number that is created with each messages. The tag take into account the AAD, the IV and the CT (*Ciphertext*), and the Key. It is made so that you can always know before deciphering if the tag match
the data you have. The tag act like an accumulator, and store in order (with 0 as padding on 16 bytes) :
- AAD
- CT
- [len(AAD) || len(CT)] (2x 8 bytes to make one 16 bytes array)
- J0 (but without ghash as it already goes through it already, so you just derive it with an AES encryption)

Every information are stored by xoring it into the tag then doing a round of ghash on the tag (every times there is the xoring process except for J0 as previously stated).

### Bit-reflection convention
The NIST documentation state specifically that when you have Gallois Field, it is in LSB/reflected (the first/left bit is x<sup>0</sup>). Why does it matter ? Because in the GHASH, you need
`pclmul`, but it works differently so you are doing the wrong operation (if not corrected after). To medle this issue you have 2 choices, first you can do it wit shufffling and crossing with
tables (slow and difficult), on another hand, you can simply continue as is but during the reduction, you can shift the result on the left by one bit then do the reduction, why ? For 2 main
reasons, one is that the bit that is lost is always null so it can be safely discarded (the bits you need for a multiplication are 2n with n the "highest" number of informations in one number,
and carry-less is 2n - 1 so for 2 xmm (128 * 2 - 1) = 255), the second is kind of weird (I struggle a lot to find a proper explanation, but it appears here "*Fast CRC Computation for Generic
Polynomials Using PCLMULQDQ Instruction*" and some recents papers talking about reflection/GCM), but the following proof shows you that a simple offset is enough to get the accumulator running
without reflection
<details>
<summary> Proofs </summary>

Taking that equation as the "reflecting" equation (A is the base A' is the reflected result) :
<br/>
A'(x) = x<sup>n-1</sup> * A(1/x)
<br/>
<br/>
We can deduce :
<br/>
A'(x) * B'(x) = x<sup>n-1</sup> * A(1/x) * x<sup>n-1</sup> * B(1/x)
<br/>
A'(x) * B'(x) = x<sup>2n-2</sup> * AB(1/x)
<br/>
A'(x) * B'(x) = (AB)'(x)
<br/>
Here it proves that reduction can be "optional" as long as you accumulated always in the same way (if you start to add/sub/... it wont work but xoring is safe).
</details>

<hr/>

## Implementation

### Key setup & H-powers precomputation
The Round key (`m_rkey`) and Hash subkey (`m_H_powers`) are key dependant only, so you can compute them in the constructor, and free them in the destructor. For the round key, see ECB_AES.md for better
understanding. As for the Hash subkey, it is computed by ciphering a 16 bytes of 0x00 to get the first 16 bytes of `m_H_powers`, and you could stop here, but for computing gf_multiply in batch, you will
need to compute other "powers" of the hash subkey, and to do that you can't use AES like before, you need to use gf_multiply with `m_H_powers.data()` (first 16 bytes), and the former degree (n - 1) of
the current one being processed `m_H_powers.data() + (i - 1) * 16` and you place the result in `m_H_powers.data() + i * 16`, so you end up with :
```
// SafeArray construct is by default set to 0
aes_encrypt<GCM_AES<N>::NR>(m_H_powers.data(), m_H_powers.data(), m_rkey.data(), 16);

bswap_block(m_H_powers.data(), m_H_powers.data()); // You need to "reflect" once the block so that gf_multiply can work on it with only offseting to correct pcmul
for (size_t i = 1; i < H_POWER_SIZE / H_SIZE; i++) {
    gf_multiply_clmul(m_H_powers.data() + (i - 1) * 16, m_H_powers.data(), m_H_powers.data() + i * 16);
}
```
Just to clarify quickly. What is pointing to what.

|        m_H_powers      |   H   |
|------------------------|-------|
| m_H_powers.data()      |   H0  |
| m_H_powers.data() + 16 |   H1  |
| m_H_powers.data() + 32 |   H2  |
| m_H_powers.data() + 48 |   H3  |


## Sources
- https://neilmadden.blog/2024/05/23/galois-counter-mode-and-random-nonces/
- https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
- https://builders.intel.com/docs/networkbuilders/advanced-encryption-standard-galois-counter-mode-optimized-ghash-function-technology-guide-1693300747.pdf
- https://www.intel.com/content/dam/www/public/us/en/documents/software-support/enabling-high-performance-gcm.pdf
- https://hal.sorbonne-universite.fr/hal-01017807v1/document

```
TODO : Transform that into the md documentation
*   gf_multiply_clmul :
*       It works using multiples optimisations, first you have to understand pclmul
*           Inputs: X,Y 
*           Output: Z=GFMUL64(X,Y)  
*               Z=0 
*               for i from 0 to 63: 
*                   Z=Z^((X<<i)&(Y[i]))
*       pclmul(qdq) works only on 64 bits numbers, and you get to choose the high/low of both xmm.
*       So armed with that knowledge, you probably wonder how we should do it right, also I will jump
*       directly on the optimised version using Karatsuba to reduce from 4 to 3 pclmul, as it has a
*       lot of latency and isn't very fast (from 4 to 7 cycles of latency for 1 cycle of executions).
*       At first (without Karatsuba) you need to do (carry-less again) A0 x B0, A1 x B0, A0 x B1, A1 x B1
*       (xmm1 = A1 (high) | A0 (low) and xmm2 = B1 (high) | B0 (low)), but with Karatsuba you now need
*       to do A0 x B0, A1 x B1 and (A1 xor A0) x (B1 xor B0). But we end up with multiples result, so
*       we need to aggregate them. The aggregation is quite easy, you just need to have 2 xmm, you have
*       in the first (high bits) A1B1 + 64 first bits of A1^A0 x B1^B0, the second xmm (low bits) A0B0 + 64 last bits
*       of A1^A0 x B1^B0 (because of Karatsuba). How do we offset it ? Using pslldq (left) and psrldq (right)
*       for 8 bytes. Nice we now have a 256 bits result from Karatsuba, but as I said you cannot have
*       a result with result higher or equal than 2^128 (remember x^128 isn't possible). But there is
*       a hitch, GCM works weirdly, as it's not LSB nor MSB, it is in bit reverse not bytes, so to prevent
*       the need of flipping everything (shuffling won't work because it moves bytes, not bits), you 
*       simply" needs to offset both xmm by one bit (proof here: "TODO/link"). But as we are implementing
*       GCM, you know it won't be that simple. You cannot simply use an << operation on xmm, you have
*       to use 13 instructions and you need to store 3 xmm for the futur (two for the lost bit on each
*       lane of each xmm) and one for the bit that overflow from the low xmm to the high xmm. Now the
*       fun part, the reduction. The reduction won't be made with simple modulo. Why ? It is slow and
*       not efficient at all. So we will take the fact that there is x^128 so far from x^7, x^2, x^1
*       and x^0. What if we use the first high xmm (255 - 128) and use it to xor the low xmm (x^0),
*       then use offset to have x^1, x^2 and x^7 ? Quite neat indeed.
```
