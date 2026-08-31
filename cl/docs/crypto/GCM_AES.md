# Summary
1. [Understanding of GCM](#understanding-of-gcm)
   - [Overall](#overall)
   - [GHASH](#ghash)
   - [Counter Block](#counter-block)
   - [Tag](#tag)
   - [Bit-reflection convention](#bit-reflection-convention)
2. [Implementation](#implementation)
   - [H-powers precomputation](#h-powers-precomputation)
   - [gf_multiply_clmul](#gf_multiply_clmul)
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

> x<sup>128</sup> + x<sup>7</sup> + x<sup>2</sup> + x + 1 = 0 (by construction of the galois field from NIST specifications, just assume it but if you want to know it is an "irreductible polynom" chosen abritrarly)<br/>
> <=>  -x<sup>128</sup> = x<sup>7</sup> + x<sup>2</sup> + x + 1<br/>
> <=>  x<sup>128</sup> = x<sup>7</sup> + x<sup>2</sup> + x + 1 (yes because we are in the Galois field where - and + are the same)
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
has no collision possible (so no reuse possible) except if your H is null) but never go higher than 16 bytes as you loose all protection against collision. Also it is really recommanded (lots of recommandation I know)
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
`pclmul`, but it works differently so you are doing the wrong operation (if not corrected after). To medle this issue you have 2 choices, first you can do it with shufffling and crossing with
tables (slow and difficult), on another hand, you can simply continue as is but during the reduction, you can shift the result on the left by one bit then do the reduction, why ? For 2 main
reasons, one is that the bit that is lost is always null so it can be safely discarded (the bits you need for a multiplication are 2n with n the "highest" number of informations in one number,
and carry-less is 2n - 1 so for 2 xmm (128 * 2 - 1) = 255), the second is kind of weird (I struggle a lot to find a proper explanation, but it appears here "*Fast CRC Computation for Generic
Polynomials Using PCLMULQDQ Instruction*" and some recents papers talking about reflection/GCM), but the following proof shows you that a simple offset is enough to get the accumulator running
without reflection
<details>
<summary> Proofs </summary>

>Taking that equation as the "reflecting" equation (A is the base A' is the reflected result) :
>
>A'(x) = x<sup>n-1</sup> * A(1/x)
>
>
>We can deduce :
>
>A'(x) * B'(x) = x<sup>n-1</sup> * A(1/x) * x<sup>n-1</sup> * B(1/x)<br/>
>A'(x) * B'(x) = x<sup>2n-2</sup> * AB(1/x)<br/>
>A'(x) * B'(x) = (AB)'(x)<br/>
>
>Here it proves that reduction can be "optional" as long as you accumulated always in the same way (if you start to add/sub/... it wont work but xoring is safe).

</details>

<hr/>

## Implementation

### H-powers precomputation
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

### gf_multiply_clmul
We first need setup the variable for the asm :
```
: [p_in] "+r"(in), [p_h] "+r"(h), [p_out] "+r"(out)
:
: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "memory", "cc"
```
The first line is for attributing read/write pointer, and the third line is for the cleanup part, it tells your compiler what should be cleaned after the block is executed.
Now we need to move the variables into registers :
```
movdqu (%[p_in]), %%xmm0    // movdqu stands for mov dual quad unaligned
movdqu (%[p_h]), %%xmm1
movdqa %%xmm0, %%xmm2       // movdqa stands for mov dual quad aligned
movdqa %%xmm0, %%xmm3
```
Because we will apply operations inside them, we need multiple copy of xmm0 that has 16 bytes of where the p_in is pointing to.

<details>
<summary> Explanantion of the pclmul (and AVX variants) </summary>

>Going forward, the gf_multiply_clmul function heavly rely on pclmul (and AVX variations), it works like this :
>```
>Inputs: X,Y 
>Output: Z=GFMUL64(X,Y)  
>    Z=0 
>    for i from 0 to 63: 
>        Z=Z^((X<<i)&(Y[i]))
>```
>pclmul(qdq) works only with 64 bits numbers to create one 128 bits result (so you get to choose the high/low of both xmm).
>To chose which you are using, you need to use `$0x00` (both low), `$0x10` (first high, second low), `$0x01` (first low, second high), `$0x11` (both high).
>
>The result is put in the last argument/register (AT&T convention), so for example :<br/>
>`pclmulqdq $0x00, %%xmm1, %%xmm2`
>
> Here we do a carry-less mulitplication on both low xmm1 and xmm2 (mulitplication of two 64 bits) and the result is set in xmm2

</details>

I will directly jump onto the Karatsuba method to reduce from 4 to 3 pclmul, as it has a lot of latency and isn't very fast (from 4 to 7 cycles of latency for 1 cycle of executions). With :
<br/>
`reg1 = A1 (high) | A0 (low)`
<br/>
`reg2 = B1 (high) | B0 (low)`

<details>
<summary> Quick look at how it works without Karatsuba </summary>

>You need to do 4 carry-less multiplications :
>
>A0 x B0<br/>
>A1 x B0<br/>
>A0 x B1<br/>
>A1 x B1<br/>
>
>Then aggregate :
>
>reg1 = A0 x B0<br/>
>reg2 = A0 x B1 + A1 x B0<br/>
>reg3 = A1 x B1<br/>
>reg1 (high) += reg2 (low)<br/>
>reg3 (low) += reg2 (high)
>
>Then reg2 can be discarded and you have 2 xmm that represent 1 number of 256 bits (or you can use 1 ymm but I won't be doing that)

</details>

But to do Karatsuba, you need to compute A1 ^ A0 and B1 ^ B0, so you will need to do a right shift of 8 bytes, so that you can have, after the xor, the result in the low part :
```
movdqa %%xmm0, %%xmm4
psrldq $8, %%xmm4       // right shift the bytes by 8 inside the register, so the 8 first bytes (in the lower half) is erase and the 8 last bytes are set in the low half
pxor %%xmm0, %%xmm4

movdqa %%xmm1, %%xmm5
psrldq $8, %%xmm5
pxor %%xmm1, %%xmm5
```

The carry-less multiplications you need to do are :
- A0 x B0 `pclmulqdq $0x00, %%xmm1, %%xmm2`
- A1 x B1 `pclmulqdq $0x11, %%xmm1, %%xmm3`
- (A1 xor A0) x (B1 xor B0) `pclmulqdq $0x00, %%xmm5, %%xmm4`

But there is an issue here, because we have (A1 xor A0) x (B1 xor B0), there is a distribution caused by the multiplication, so you need to substract it, hence :
```
pxor %%xmm2, %%xmm4
pxor %%xmm3, %%xmm4
```

But here we have 3 different results, when we should have 2 for a 256 bits result. So we need to aggregate them, and to do so, we will do as such (each square bracket represent 64 bits) : <br/>
`[ A0 x B0 (low) ]` `[ A0 x B0 (high) + ((A1 xor A0) x (B1 xor B0) (low)) ]` `[ A1 x B1 (low) + ((A1 xor A0) x (B1 xor B0) (high)) ]` `[ A1 x B1 (high) ] `
<br/>You need to offset by 8 bytes the 2 registers on the left and right then add it to the others 2 registers :
```
movdqa %%xmm4, %%xmm5
pslldq $8, %%xmm5       // left shift
psrldq $8, %%xmm4       // left shift

pxor %%xmm4, %%xmm3
pxor %%xmm5, %%xmm2
```

Now that we are here we have a 255 bits (256 - 1) of information, but remember, we cannot have more than 128 bits of informations, so we need to start the reduction process, but before that we need
to offset by one bit (remember, the bit-reflecting conventions). The issue here is that there is no operations that let you shift by one bit a whole register, you need a 13 instructions steps (all that for
a simple bit shift lmao and it's the most conceptualy difficult part of the whole implementation).

<details>
<summary> Operation needed </summary>

> To achieve a bit shift on SIMD registers (not the global one), there is no bit shifting across the whole registers available, but others exists, you have :
> <br/>
>
> `psrld`/`pslld` move **bits** inside the register as 4 independants intergers (each of 4 bytes), what does that mean, if for example I shift by 8 on the right, I would have lost 32 bits because of that shift. How ?
> Because as said previously the integers are independant, and the shift doesn't cross between them, so you would have<br/>
> [ 00000000 (result of the r_shift) + 10101010...1 (the shifted result but with the last 8 bits erased) ] [ 00000000 + 01010101...0  ] [ 0 x 8 + ... ] [ 0 x 8 + ... ]
> <br/>
>
> `psrldq`/`pslldq` move **bytes** without limitation across the whole register

</details>

You need to have a carry of the lost bits for the shift, so you need to save those bits lost (here in xmm4 and xmm5), then store separatly the bit that will
jump from one register to another (in xmm7), then offset them by 4 bytes, then add them back with a or/xor
```
movdqa %%xmm2, %%xmm4
psrld $31, %%xmm4       // discard everything exept the 4 rightest bits (x^31, x^63, x^95, x^127) on the left side (x^0, x^32, x^64, x^96)
movdqa %%xmm3, %%xmm5
psrld $31, %%xmm5       // same but for xmm3
pslld $1, %%xmm2        // the destructive shift that looses the bits that we just stored before
pslld $1, %%xmm3

movdqa %%xmm4, %%xmm7   // setup for the correction of the carried bit
psrldq $12, %%xmm7      // discarding every bits stored except of the one that will go across one register to the other one (so only the x^127)
pslldq $4, %%xmm4       // shifting every bits saved by 4 bytes (remember the fact that psrld work on 4 independants integers, so each 4 bytes)
pslldq $4, %%xmm5
por %%xmm4, %%xmm2      // here we use por but pxor would work just fine because we know that they are 0
por %%xmm5, %%xmm3
por %%xmm7, %%xmm3
```
TODO : finish


## Sources
- https://neilmadden.blog/2024/05/23/galois-counter-mode-and-random-nonces/
- https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
- https://builders.intel.com/docs/networkbuilders/advanced-encryption-standard-galois-counter-mode-optimized-ghash-function-technology-guide-1693300747.pdf
- https://www.intel.com/content/dam/www/public/us/en/documents/software-support/enabling-high-performance-gcm.pdf
- https://hal.sorbonne-universite.fr/hal-01017807v1/document
