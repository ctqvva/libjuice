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

	entry.state = AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE;
	entry.transaction_id_expired = true;
	if (!agent_stun_entry_matches_transaction_id(&entry, transaction_id))
		return -1;

	entry.state = AGENT_STUN_ENTRY_STATE_FAILED;
	if (agent_stun_entry_matches_transaction_id(&entry, transaction_id))
		return -1;

	return 0;
}

int test_consent_suspend_deadline(void) {
	ice_candidate_pair_t pair;
	memset(&pair, 0, sizeof(pair));

	/* A 60-second suspend advances scheduling time but not active consent time. */
	const timestamp_t scheduler_now = 160000;
	const timestamp_t consent_now = 100000;
	pair.consent_expiry = consent_now + CONSENT_TIMEOUT;

	if (agent_pair_consent_expired(&pair, consent_now))
		return -1;
	if (agent_pair_consent_scheduler_deadline(&pair, scheduler_now, consent_now) !=
	    scheduler_now + CONSENT_TIMEOUT)
		return -1;

	if (!agent_pair_consent_expired(&pair, pair.consent_expiry))
		return -1;
	if (agent_pair_consent_scheduler_deadline(&pair, scheduler_now, pair.consent_expiry) !=
	    scheduler_now)
		return -1;

	return 0;
}
