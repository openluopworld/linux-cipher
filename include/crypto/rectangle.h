// SPDX-License-Identifier: GPL-2.0
/*
 * Common values for the RECTANGLE algorithm
 */

#ifndef _CRYPTO_RECTANGLE_H
#define _CRYPTO_RECTANGLE_H

#include <linux/types.h>

#define RECTANGLE_BLOCK_SIZE	 (8)
#define RECTANGLE_80_KEY_SIZE	 (10)
#define RECTANGLE_128_KEY_SIZE   (16)
#define RECTANGLE_ROUNDS	 (25)
#define RECTANGLE_ROUND_KEY_SIZE (208)

struct rectangle_tfm_ctx {
	u8  round_keys[RECTANGLE_ROUND_KEY_SIZE];
	int nrounds;
};

void crypto_rectangle_encrypt(const struct rectangle_tfm_ctx *ctx,
			     u8 *out, const u8 *in);

void crypto_rectangle_decrypt(const struct rectangle_tfm_ctx *ctx,
			      u8 *out, const u8 *in);

int crypto_rectangle_setkey(struct rectangle_tfm_ctx *ctx, const u8 *key,
			    unsigned int keysize);

#endif /* _CRYPTO_RECTANGLE_H */
