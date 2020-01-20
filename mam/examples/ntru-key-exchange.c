/*
 * Copyright (c) 2019 IOTA Stiftung
 * https:github.com/iotaledger/entangled
 *
 * MAM is based on an original implementation & specification by apmi.bsu.by
 * [ITSec Lab]
 *
 * Refer to the LICENSE file for licensing information
 */

#include <stdio.h>
#include "mam/api/api.h"
#include "mam/ntru/ntru.h"

#define SENDERSEED "SENDERSEED9SENDERSEED9SENDERSEED9SENDERSEED9SENDERSEED9SENDERSEED9SENDERSEED99999"
#define SENDER2SEED "SENDERSEED9TWO9SENDERSEED9SENDERSEED9SENDERSEED9SENDERSEED9SENDERSEED9SENDERSEED9"
#define RECEIVERSEED "RECEIVERSEED9RECEIVERSEED9RECEIVERSEED9RECEIVERSEED9RECEIVERSEED9RECEIVERSEED9999"
#define NONCE "ABCDEFGHI"
#define PL "PAYLOADTEST"

int main() {
  retcode_t ret = RC_OK;
  // Setting up two sender APIs
  mam_api_t sender_api;
  tryte_t *sender_seed = (tryte_t *)SENDERSEED;
  ERR_BIND_RETURN(mam_api_init(&sender_api, sender_seed), ret);
  mam_api_t sender2_api;
  tryte_t *sender2_seed = (tryte_t *)SENDER2SEED;
  ERR_BIND_RETURN(mam_api_init(&sender2_api, sender2_seed), ret);
  // Setting up receiver API
  mam_api_t receiver_api;
  tryte_t *receiver_seed = (tryte_t *)RECEIVERSEED;
  ERR_BIND_RETURN(mam_api_init(&receiver_api, receiver_seed), ret);
  // Generating a keypair for the receiver api
  mam_ntru_sk_t ntru;
  MAM_TRITS_DEF(nonce, 3 * 9);
  nonce = MAM_TRITS_INIT(nonce, 3 * 9);
  trits_from_str(nonce, NONCE);
  ntru_sk_reset(&ntru);
  ntru_sk_gen(&ntru, &receiver_api.prng, nonce);
  // Setting the generated keypair to the receiver API
  ERR_BIND_RETURN(mam_api_add_ntru_sk(&receiver_api, &ntru), ret);
  // Adding the receiver APIs public key to the sender APIs public key list
  ERR_BIND_RETURN(mam_api_add_ntru_pk(&sender_api, &ntru.public_key), ret);
  ERR_BIND_RETURN(mam_api_add_ntru_pk(&sender2_api, &ntru.public_key), ret);
  // Preparing channel and endpoint with sender APIs with randomly chosen height
  tryte_t channel_id[MAM_CHANNEL_ID_TRYTE_SIZE];
  ERR_BIND_RETURN(mam_api_channel_create(&sender_api, 2, channel_id), ret);
  tryte_t endpoint_id[MAM_ENDPOINT_ID_TRYTE_SIZE];
  ERR_BIND_RETURN(mam_api_endpoint_create(&sender_api, 2, channel_id, endpoint_id), ret);
  tryte_t channel2_id[MAM_CHANNEL_ID_TRYTE_SIZE];
  ERR_BIND_RETURN(mam_api_channel_create(&sender2_api, 2, channel2_id), ret);
  tryte_t endpoint2_id[MAM_ENDPOINT_ID_TRYTE_SIZE];
  ERR_BIND_RETURN(mam_api_endpoint_create(&sender2_api, 2, channel2_id, endpoint2_id), ret);
  // prepare bundles for sender APIs to write to
  bundle_transactions_t *bundle = NULL;
  bundle_transactions_new(&bundle);
  bundle_transactions_t *bundle2 = NULL;
  bundle_transactions_new(&bundle2);
  // prepare and write headers and packets
  trit_t message_id[MAM_MSG_ID_SIZE];
  ERR_BIND_RETURN(mam_api_bundle_write_header_on_endpoint(&sender_api, channel_id, endpoint_id, NULL,
                                                          sender_api.ntru_pks, bundle, message_id),
                  ret);
  ERR_BIND_RETURN(mam_api_bundle_write_packet(&sender_api, message_id, (tryte_t *)PL, strlen(PL), MAM_MSG_CHECKSUM_SIG,
                                              true, bundle),
                  ret);
  trit_t message2_id[MAM_MSG_ID_SIZE];
  ERR_BIND_RETURN(mam_api_bundle_write_header_on_endpoint(&sender2_api, channel2_id, endpoint2_id, NULL,
                                                          sender2_api.ntru_pks, bundle2, message2_id),
                  ret);
  ERR_BIND_RETURN(mam_api_bundle_write_packet(&sender2_api, message2_id, (tryte_t *)PL, strlen(PL), MAM_MSG_CHECKSUM_SIG,
                                              true, bundle2),
                  ret);
  // Set created channel and endpoint as trusted in receiver API
  ERR_BIND_RETURN(mam_api_add_trusted_channel_pk(&receiver_api, channel2_id), ret);
  ERR_BIND_RETURN(mam_api_add_trusted_endpoint_pk(&receiver_api, endpoint2_id), ret);
  ERR_BIND_RETURN(mam_api_add_trusted_channel_pk(&receiver_api, channel_id), ret);
  ERR_BIND_RETURN(mam_api_add_trusted_endpoint_pk(&receiver_api, endpoint_id), ret);
  
  // read the bundle with the receiver API and print the decrypted payload
  tryte_t *payload = NULL;
  size_t payload_size = 0;
  bool is_last_packet = false;
  ERR_BIND_RETURN(mam_api_bundle_read(&receiver_api, bundle, &payload, &payload_size, &is_last_packet), ret);
  fprintf(stderr, "Payload: ");
  for (size_t i = 0; i < payload_size; i++) {
    fprintf(stderr, "%c", payload[i]);
  }
  fprintf(stderr, "\n");
  printf("%d\n", is_last_packet); // prints 1
  tryte_t *payload2 = NULL;
  size_t payload_size2 = 0;
  bool is_last_packet2 = false;
  ERR_BIND_RETURN(mam_api_bundle_read(&receiver_api, bundle2, &payload2, &payload_size2, &is_last_packet2), ret);
  fprintf(stderr, "Payload2: ");
  for (size_t i = 0; i < payload_size2; i++) {
    fprintf(stderr, "%c", payload2[i]);
  }
  fprintf(stderr, "\n");
  printf("%d\n", is_last_packet2); // prints 1
  // free ressources
  free(payload);
  free(payload2);
  bundle_transactions_free(&bundle);
  bundle_transactions_free(&bundle2);
  mam_api_destroy(&sender_api);
  mam_api_destroy(&sender2_api);
  mam_api_destroy(&receiver_api);
  // finished
  return ret;
}
