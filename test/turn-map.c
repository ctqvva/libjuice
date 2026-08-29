/**
 * Copyright (c) 2026
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "addr.h"
#include "turn.h"

#include <stdint.h>
#include <string.h>

int main(void) {
	addr_record_t first;
	addr_record_t second;
	if (addr_resolve("192.0.2.1", "5000", SOCK_DGRAM, &first, 1) != 1 ||
	    addr_resolve("192.0.2.1", "5001", SOCK_DGRAM, &second, 1) != 1)
		return -1;

	turn_map_t map;
	if (turn_init_map(&map, 8) < 0)
		return -1;

	int result = 0;
	const timediff_t lifetime = 60000;
	if (!turn_bind_channel(&map, &first, NULL, 0x4000, lifetime) ||
	    !turn_bind_channel(&map, &second, NULL, 0x4001, lifetime)) {
		result = -1;
	} else {
		uint16_t first_channel = 0;
		uint16_t second_channel = 0;
		if (!turn_get_channel(&map, &first, &first_channel) ||
		    !turn_get_channel(&map, &second, &second_channel) ||
		    first_channel != 0x4000 || second_channel != 0x4001)
			result = -1;
	}

	uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE];
	memset(transaction_id, 1, sizeof(transaction_id));
	if (!turn_set_permission(&map, transaction_id, &first, lifetime) ||
	    !turn_has_permission(&map, &second))
		result = -1;

	turn_destroy_map(&map);
	return result;
}
