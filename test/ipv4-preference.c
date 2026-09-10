#include "ice.h"
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "IPv4 preference check failed at line %d\n", __LINE__); return -1; } } while (0)

typedef struct { atomic_bool gathered; atomic_bool received; } peer_state;
static void gathered(juice_agent_t *agent, void *user) {
    (void)agent;
    atomic_store(&((peer_state *)user)->gathered, true);
}
static void received(juice_agent_t *agent, const char *data, size_t size, void *user) {
    (void)agent;
    if (size == 4 && memcmp(data, "ping", 4) == 0)
        atomic_store(&((peer_state *)user)->received, true);
}

static int live_pair(bool prefer_ipv4, const char *bind_address, int expected_family) {
    peer_state states[2] = {0};
    juice_agent_t *agents[2] = {0};
    int result = -1;
    for (int i = 0; i < 2; ++i) {
        juice_config_t config = {0};
        config.bind_address = bind_address;
        config.prefer_ipv4 = prefer_ipv4;
        config.cb_gathering_done = gathered;
        config.cb_recv = received;
        config.user_ptr = &states[i];
        agents[i] = juice_create(&config);
        if (!agents[i] || juice_gather_candidates(agents[i])) goto done;
    }
    for (int attempt = 0; attempt < 500; ++attempt) {
        if (atomic_load(&states[0].gathered) && atomic_load(&states[1].gathered)) break;
        usleep(10000);
    }
    if (!atomic_load(&states[0].gathered) || !atomic_load(&states[1].gathered)) goto done;
    for (int i = 0; i < 2; ++i) {
        char description[JUICE_MAX_SDP_STRING_LEN];
        if (juice_get_local_description(agents[i], description, sizeof(description)) ||
            juice_set_remote_description(agents[1-i], description)) goto done;
        juice_set_remote_gathering_done(agents[1-i]);
    }
    for (int attempt = 0; attempt < 500; ++attempt) {
        if (juice_get_state(agents[0]) == JUICE_STATE_COMPLETED &&
            juice_get_state(agents[1]) == JUICE_STATE_COMPLETED) break;
        usleep(10000);
    }
    for (int i = 0; i < 2; ++i) {
        char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN], remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
        ice_candidate_t candidate;
        if (juice_get_state(agents[i]) != JUICE_STATE_COMPLETED ||
            juice_get_selected_candidates(agents[i], local, sizeof(local), remote, sizeof(remote)) ||
            ice_parse_candidate_sdp(local, &candidate) ||
            candidate.resolved.addr.ss_family != expected_family) goto done;
        if (juice_send(agents[i], "ping", 4)) goto done;
    }
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (atomic_load(&states[0].received) && atomic_load(&states[1].received)) break;
        usleep(10000);
    }
    if (atomic_load(&states[0].received) && atomic_load(&states[1].received)) result = 0;
done:
    for (int i = 0; i < 2; ++i) if (agents[i]) juice_destroy(agents[i]);
    if (result) fprintf(stderr, "Live ICE pair failed: prefer_ipv4=%d bind=%s expected_family=%d\n",
        prefer_ipv4, bind_address ? bind_address : "dual-stack", expected_family);
    return result;
}

int main(void) {
    const ice_candidate_type_t types[] = {ICE_CANDIDATE_TYPE_HOST,
        ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
        ICE_CANDIDATE_TYPE_RELAYED};
    for (unsigned t = 0; t < sizeof(types) / sizeof(types[0]); ++t) {
        for (int index = 0; index <= 4095; index += 4095) {
            uint32_t old4 = ice_compute_priority(types[t], AF_INET, 1, index, ICE_CANDIDATE_TRANSPORT_UDP);
            uint32_t old6 = ice_compute_priority(types[t], AF_INET6, 1, index, ICE_CANDIDATE_TRANSPORT_UDP);
            uint32_t new4 = ice_compute_priority_with_preference(types[t], AF_INET, 1, index, ICE_CANDIDATE_TRANSPORT_UDP, true);
            uint32_t new6 = ice_compute_priority_with_preference(types[t], AF_INET6, 1, index, ICE_CANDIDATE_TRANSPORT_UDP, true);
            CHECK(old6 > old4 && new4 > new6);
            CHECK(old4 == new6 && old6 == new4);
            CHECK(old4 == ice_compute_priority_with_preference(types[t], AF_INET, 1, index, ICE_CANDIDATE_TRANSPORT_UDP, false));
            CHECK(old6 == ice_compute_priority_with_preference(types[t], AF_INET6, 1, index, ICE_CANDIDATE_TRANSPORT_UDP, false));
        }
    }
    CHECK(ice_compute_priority(ICE_CANDIDATE_TYPE_HOST, AF_INET6, 1, 0, ICE_CANDIDATE_TRANSPORT_UDP)
        == ((126u << 24) + (8191u << 8) + 255));
    uint32_t relay4 = ice_compute_priority_with_preference(ICE_CANDIDATE_TYPE_RELAYED, AF_INET, 1, 0, ICE_CANDIDATE_TRANSPORT_UDP, true);
    for (unsigned t = 0; t < 3; ++t)
        CHECK(ice_compute_priority_with_preference(types[t], AF_INET6, 1, 4095, ICE_CANDIDATE_TRANSPORT_UDP, true) > relay4);

    ice_candidate_t candidates[2][2];
    for (int prefer = 0; prefer < 2; ++prefer) {
        for (int family = 0; family < 2; ++family) {
            addr_record_t record;
            memset(&record, 0, sizeof(record));
            record.socktype = SOCK_DGRAM;
            record.addr.ss_family = family ? AF_INET6 : AF_INET;
            record.len = family ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
            CHECK(ice_create_local_candidate(ICE_CANDIDATE_TYPE_HOST, 1, 0, &record,
                &candidates[prefer][family], ICE_CANDIDATE_TRANSPORT_UDP, prefer) == 0);
            // Address family is not filtered or rewritten by the preference.
            CHECK(candidates[prefer][family].resolved.addr.ss_family == record.addr.ss_family);
        }
        for (int controlling = 0; controlling < 2; ++controlling) {
            ice_candidate_pair_t pairs[2];
            for (int family = 0; family < 2; ++family)
                CHECK(ice_create_candidate_pair(&candidates[prefer][family], &candidates[prefer][family],
                    controlling, &pairs[family], prefer) == 0);
            CHECK(prefer ? pairs[0].priority > pairs[1].priority : pairs[1].priority > pairs[0].priority);
            // A generic local candidate must use the same policy after a role change.
            for (int family = 0; family < 2; ++family) {
                CHECK(ice_create_candidate_pair(NULL, &candidates[prefer][family], controlling,
                    &pairs[family], prefer) == 0);
                CHECK(ice_update_candidate_pair(&pairs[family], !controlling) == 0);
            }
            CHECK(prefer ? pairs[0].priority > pairs[1].priority : pairs[1].priority > pairs[0].priority);
        }
    }
    CHECK(live_pair(false, NULL, AF_INET6) == 0);
    CHECK(live_pair(true, NULL, AF_INET) == 0);
    CHECK(live_pair(true, "::1", AF_INET6) == 0);
    puts("PASS priorities and live ICE: default IPv6, preferred IPv4, IPv6-only fallback, bidirectional delivery");
    return 0;
}
