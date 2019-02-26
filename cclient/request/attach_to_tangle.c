/*
 * Copyright (c) 2018 IOTA Stiftung
 * https://github.com/iotaledger/entangled
 *
 * Refer to the LICENSE file for licensing information
 */

#include "cclient/request/attach_to_tangle.h"

attach_to_tangle_req_t* attach_to_tangle_req_new() {
  attach_to_tangle_req_t* req =
      (attach_to_tangle_req_t*)malloc(sizeof(attach_to_tangle_req_t));
  if (req) {
    req->mwm = ATTACH_TO_TANGLE_MAIN_MWM;
    req->trytes = NULL;
    memset(req->trunk, FLEX_TRIT_NULL_VALUE, FLEX_TRIT_SIZE_243);
    memset(req->branch, FLEX_TRIT_NULL_VALUE, FLEX_TRIT_SIZE_243);
  }
  return req;
}

void attach_to_tangle_req_free(attach_to_tangle_req_t** req) {
  if (!req || !(*req)) {
    return;
  }

  free(*req);
  *req = NULL;
}

void attach_to_tangle_req_init(attach_to_tangle_req_t* req,
                               flex_trit_t const* const trunk,
                               flex_trit_t const* const branch, int32_t mwm) {
  memcpy(req->trunk, trunk, FLEX_TRIT_SIZE_243);
  memcpy(req->trunk, branch, FLEX_TRIT_SIZE_243);
  req->mwm = mwm;
}

void attach_to_tangle_req_add_trytes(attach_to_tangle_req_t* req,
                                     flex_trit_t const* const raw_trytes) {
  hash_array_push(req->trytes, raw_trytes);
}
