/**
 * Copyright (c) 2026
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "agent.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

int test_consent_transaction_expiry(void) {
	agent_stun_entry_t entry;
	memset(&entry, 0, sizeof(entry));

	uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE];
	for (size_t i = 0; i < sizeof(transaction_id); ++i)
		transaction_id[i] = (uint8_t)(i + 1);
	memcpy(entry.transaction_id, transaction_id, sizeof(transaction_id));

	entry.transaction_id_expired = false;
	if (!agent_stun_entry_matches_transaction_id(&entry, transaction_id))
		return -1;

	entry.transaction_id_expired = true;
	if (agent_stun_entry_matches_transaction_id(&entry, transaction_id))
		return -1;

	return 0;
}
