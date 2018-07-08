/*
 * RECTANGLE: A ligitweight block cipher
 *
 * Copyright (c) 2018 Luo Peng <luopengxq@gmail.com>
 *
 * Common values for the RECTANGLE algorithm
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
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
	union round_keys {
		u8  rk8[RECTANGLE_ROUND_KEY_SIZE];
		u16 rk16[RECTANGLE_ROUND_KEY_SIZE/2];
		u32 rk32[RECTANGLE_ROUND_KEY_SIZE/4];
	} round_keys;
};

void crypto_rectangle_encrypt(const struct rectangle_tfm_ctx *ctx,
			     u8 *out, const u8 *in);

void crypto_rectangle_decrypt(const struct rectangle_tfm_ctx *ctx,
			      u8 *out, const u8 *in);

int crypto_rectangle_setkey(struct rectangle_tfm_ctx *ctx, const u8 *key,
			    unsigned int keysize);

#endif /* _CRYPTO_RECTANGLE_H */
