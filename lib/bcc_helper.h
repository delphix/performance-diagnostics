/*
 * Copyright (c) 2019 by Delphix. All rights reserved.
 */

// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * This file contains helper utilities to write bcc scripts for delphix
 * analytics and other bcc scripts.
 */


/* Structure used in average aggregations and zero initializer value */
typedef struct average {
	u64 count;
	u64 sum;
} average_t;

#define	ZERO_AVERAGE {0, 0}


/* define histogram key type with the aggregation key and a slot */
#define	HIST_KEY(hist_key_type, agg_key_type) \
typedef struct { \
	agg_key_type	agg_key; \
	u64		slot; \
} hist_key_type;

/*
 * This function returns the slot, or histogram bucket, for a value based
 * on log linear distribution equivalent to dtrace llquantize(*, 10, 4, 10, 10).
 * The maximum islot returned is 60 for values greater than 10^10.
 */
static u64 log_lin_hist_slot(u64 value)
{
	u64 islot = 0;
	u64 mag = 10000;

	if (value < mag)
		return (islot);

	for (int imag = 4; imag < 10; imag++) {
		u64 nmag = mag * 10;
		if (value > nmag) {
			islot = islot + 10;
			mag = nmag;
		} else {
			islot += value / mag;
			break;
		}
	}

	return (islot);
}
