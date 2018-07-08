// SPDX-License-Identifier: GPL-2.0
/*
 * RECTANGLE: a lightweight block cipher
 *
 */

#include <asm/unaligned.h>
#include <crypto/rectangle.h>
#include <linux/bitops.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/module.h>

void crypto_rectangle_encrypt(const struct rectangle_tfm_ctx *ctx,
			      u8 *out, const u8 *in)
{
	u16 sbox0, sbox1;
	int i;

	u16 *rks16 = (const u16*)ctx->round_keys;
	u16 w0 = *(const u16*)in;
	u16 w1 = *((const u16*)in+1);
	u16 w2 = *((const u16*)in+2);
	u16 w3 = *((const u16*)in+3);

	for ( i = 0; i < RECTANGLE_ROUNDS; ++i ) {
		// AddRoundKey
		w0 ^= *(rks16++);
		w1 ^= *(rks16++);
		w2 ^= *(rks16++);
		w3 ^= *(rks16++);
		// SubColumn
		sbox1 =  ~w1;
		sbox0 =  sbox1 | w3;
		sbox0 ^= w0;
		w0    &= sbox1;
		sbox1 =  w2 ^ w3;
		w0    ^= sbox1;
		w3    =  w1 ^ w2;
		w1    =  w2 ^ sbox0;
		sbox1 &= sbox0;
		w3    ^= sbox1;
		w2    =  w0 | w3;
		w2    ^= sbox0;
		// ShiftRow
		w1 = (w1<<1  | w1 >> 15);
		w2 = (w2<<12 | w2 >> 4);
		w3 = (w3<<13 | w3 >> 3);
	}
	// last AddRoundKey
	w0 ^= *(rks16++);
	w1 ^= *(rks16++);
	w2 ^= *(rks16++);
	w3 ^= *rks16;
	// out text
	*(u16*)out     = w0;
	*((u16*)out+1) = w1;
	*((u16*)out+2) = w2;
	*((u16*)out+3) = w3;
}
EXPORT_SYMBOL_GPL(crypto_rectangle_encrypt);

static void rectangle_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	crypto_rectangle_encrypt(crypto_tfm_ctx(tfm), out, in);
}

void crypto_rectangle_decrypt(const struct rectangle_tfm_ctx *ctx,
			      u8 *out, const u8 *in)
{
	u16 sbox0, sbox1, sbox2, sbox3;
	int i;

	const u16 *rks16 = (const u16*)ctx->round_keys;
	u16 w0 = *(const u16*)in;
	u16 w1 = *((const u16*)in+1);
	u16 w2 = *((const u16*)in+2);
	u16 w3 = *((const u16*)in+3);

	rks16 += 100;

	for ( i = 0; i < RECTANGLE_ROUNDS; ++i ) {
		// AddRoundKey
		w0 ^= *rks16;
		w1 ^= *(rks16+1);
		w2 ^= *(rks16+2);
		w3 ^= *(rks16+3);
		rks16 -= 4;
		// Inverse ShiftRow
		w1 = (w1>>1  | w1 << 15);
		w2 = (w2>>12 | w2 << 4);
		w3 = (w3>>13 | w3 << 3);
		// Invert SubColumn
		sbox2 =  w0 ^ w1;
		sbox0 =  w0 | w3;
		sbox0 ^= w2;
		w2    =  w1 ^ sbox0;
		sbox1 =  w0 & sbox0;
		sbox1 ^= w3;
		w1    =  sbox1 ^ w2;
		sbox3 =  ~w1;
		sbox1 =  sbox0 | sbox3;;
		w3    =  sbox1 ^ sbox2;
		sbox1 =  w3 | sbox3;
		w0    =  sbox0 ^ sbox1;
	}
	// last AddRoundKey
	w0 ^= *rks16;
	w1 ^= *(rks16+1);
	w2 ^= *(rks16+2);
	w3 ^= *(rks16+3);
	// out text
	*(u16*)out     = w0;
	*((u16*)out+1) = w1;
	*((u16*)out+2) = w2;
	*((u16*)out+3) = w3;
}
EXPORT_SYMBOL_GPL(crypto_rectangle_decrypt);

static void rectangle_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	crypto_rectangle_decrypt(crypto_tfm_ctx(tfm), out, in);
}

static void rectangle_key_schedule_80(struct rectangle_tfm_ctx *ctx,
				      const u8 *key)
{
	rec_key80 mk;
	u16 *rks16 = (u16*)ctx->round_keys;
	u8 sbox0, sbox1;
	u8 temp[4];
	u16 tempk0;
	u8 i;
	u8 count = 0;

	rks16[count++] = mk.k16[0] = *((u16*)key);
	rks16[count++] = mk.k16[1] = *((u16*)key+1);
	rks16[count++] = mk.k16[2] = *((u16*)key+2);
	rks16[count++] = mk.k16[3] = *((u16*)key+3);
	mk.k16[4] = *((u16*)key+4);

	for ( i = 0; i < RECTANGLE_ROUNDS; ++i ) {
		temp[0] = mk.k8[0];
		temp[1] = mk.k8[2];
		temp[2] = mk.k8[4];
		temp[3] = mk.k8[6];
		// S box
		sbox1    =  ~mk.k8[2];
		sbox0    =  sbox1 | mk.k8[6];
		sbox0    ^= mk.k8[0];
		mk.k8[0] &= sbox1;
		sbox1    =  mk.k8[4] ^ mk.k8[6];
		mk.k8[0] ^= sbox1;
		mk.k8[6] =  mk.k8[2] ^ mk.k8[4];
		mk.k8[2] =  mk.k8[4] ^ sbox0;
		sbox1    &= sbox0;
		mk.k8[6] ^= sbox1;
		mk.k8[4] =  mk.k8[0] | mk.k8[6];
		mk.k8[4] ^= sbox0;
		// just change the lowest nibble
		mk.k8[0] = (mk.k8[0]&0x0f) ^ (temp[0]&0xf0);
		mk.k8[2] = (mk.k8[2]&0x0f) ^ (temp[1]&0xf0);
		mk.k8[4] = (mk.k8[4]&0x0f) ^ (temp[2]&0xf0);
		mk.k8[6] = (mk.k8[6]&0x0f) ^ (temp[3]&0xf0);
		// shift rows
		tempk0    =  mk.k16[0];
		mk.k16[0] =  mk.k16[1] ^ ( tempk0<<8 | tempk0>>8 );
		mk.k16[1] =  mk.k16[2];
		mk.k16[2] =  mk.k16[3];
		mk.k16[3] =  mk.k16[4] ^ ( mk.k16[3]<<12 | mk.k16[3]>>4 );
		mk.k16[4] =  tempk0;
		// round constants
		mk.k8[0] ^= RC[i];
		// store round key
		rks16[count++] = mk.k16[0];
		rks16[count++] = mk.k16[1];
		rks16[count++] = mk.k16[2];
		rks16[count++] = mk.k16[3];
	}
}

static void rectangle_key_schedule_80(struct rectangle_tfm_ctx *ctx,
				      const u8 *key)
	rec_key128 mk;
	u16 *rks16 = (u16*)ctx->round_keys;
	u8 sbox0, sbox1;
	u16 halfRow2;
	u32 tempRow0;
	u8 i;
	u8 count = 0;

	mk.k32[0] = *((u32*)key);
	mk.k32[1] = *((u32*)key+1);
	mk.k32[2] = *((u32*)key+2);
	mk.k32[3] = *((u32*)key+3);
	// the first round
	rks16[count++] = mk.k16[0];
	rks16[count++] = mk.k16[2];
	rks16[count++] = mk.k16[4];
	rks16[count++] = mk.k16[6];

	for ( i = 0; i < RECTANGLE_ROUNDS; ++i ) {
		// S box
		sbox1     = ~mk.k8[4];
		sbox0     = sbox1 | mk.k8[12];
		sbox0     ^= mk.k8[0];
		mk.k8[0]  &= sbox1;
		sbox1     = mk.k8[8] ^ mk.k8[12];
		mk.k8[0]  ^= sbox1;
		mk.k8[12] = mk.k8[4] ^ mk.k8[8];
		mk.k8[4]  = mk.k8[8] ^ sbox0;
		sbox1     &= sbox0;
		mk.k8[12] ^= sbox1;
		mk.k8[8]  = mk.k8[0] | mk.k8[12];
		mk.k8[8]  ^= sbox0;
		// row
		tempRow0  = mk.k32[0];
		mk.k32[0] = (tempRow0<<8 | tempRow0>>24) ^ mk.k32[1];
		mk.k32[1] = mk.k32[2];
		halfRow2  = mk.k16[4];
		mk.k16[4] = mk.k16[5] ^ mk.k16[6];
		mk.k16[5] = halfRow2  ^ mk.k16[7];
		mk.k32[3] = tempRow0;
		// round constants
		mk.k8[0] ^= RC[i];
		// store round key
		rks16[count++] = mk.k16[0];
		rks16[count++] = mk.k16[2];
		rks16[count++] = mk.k16[4];
		rks16[count++] = mk.k16[6];
	}
}

int crypto_rectangle_setkey(struct rectangle_tfm_ctx *ctx, const u8 *key,
			  unsigned int keylen)
{
	switch (keylen) {
	case RECTANGLE_80_KEY_SIZE:
		rectangle_key_schedule_80(ctx, key);
		break;
	case RECTANGLE_128_KEY_SIZE:
		rectangle_key_schedule_128(ctx, key);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(crypto_rectangle_setkey);

static int rectangle_setkey(struct crypto_tfm *tfm, const u8 *key,
			  unsigned int keylen)
{
	return crypto_rectangle_setkey(crypto_tfm_ctx(tfm), key, keylen);
}

/* Algorithm definitions */

static struct crypto_alg rectangle_algs[] = {
	{
		.cra_name		= "rectangle",
		.cra_driver_name	= "rectangle-generic",
		.cra_priority		= 100,
		.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
		.cra_blocksize		= RECTANGLE_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct rectangle_tfm_ctx),
		.cra_module		= THIS_MODULE,
		.cra_u			= {
			.out = {
				.cia_min_keysize	= RECTANGLE_80_KEY_SIZE,
				.cia_max_keysize	= RECTANGLE_128_KEY_SIZE,
				.cia_setkey		= rectangle_setkey,
				.cia_encrypt		= rectangle_encrypt,
				.cia_decrypt		= rectangle_decrypt
			}
		}
	}
};

static int __init rectangle_module_init(void)
{
	return crypto_register_algs(rectangle_algs, ARRAY_SIZE(rectangle_algs));
}

static void __exit rectangle_module_exit(void)
{
	crypto_unregister_algs(rectangle_algs, ARRAY_SIZE(rectangle_algs));
}

module_init(rectangle_module_init);
module_exit(rectangle_module_exit);

MODULE_DESCRIPTION("RECTANGLE block out (generic)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("LuoPeng <luopengxq@gmail.com>");
MODULE_ALIAS_CRYPTO("rectangle");
MODULE_ALIAS_CRYPTO("rectangle-generic");
