//! Known-answer-test (KAT) vectors for Xray v25.x REALITY wire-compat.
//!
//! All vectors in this file are placeholders. Capturing real fixtures
//! requires a self-hosted Xray v25.x server with a known `private_key`
//! so we can derive the expected `auth_key` offline and compare against
//! the bytes on the wire. The capture procedure is in
//! [docs/test-vectors.md]. Until we run it, every test below exits via
//! `error.SkipZigTest` so the suite stays green.
//!
//! Once the vectors land, replace `return error.SkipZigTest` with
//! the byte-exact assertions and delete this note.

const std = @import("std");

test "KAT: Xray v25.x ClientHello -> AuthKey (capture pending)" {
    // TODO(capture): populate from docs/test-vectors.md capture #1.
    //   Input:  raw ClientHello bytes captured via tshark.
    //   Input:  server private_key + short_id used by the live server.
    //   Input:  unix_ms stamped into session_id by the client.
    //   Expect: xray_wire.verifyClientHello returns VerifiedSession
    //           with .material.auth_key equal to the offline-derived value.
    return error.SkipZigTest;
}

test "KAT: Xray v25.x AuthKey -> AuthMAC (capture pending)" {
    // TODO(capture): populate from docs/test-vectors.md capture #2.
    //   Input:  auth_key derived above.
    //   Input:  ClientHello bytes with auth_mac slot zeroed.
    //   Expect: HMAC-SHA256(auth_key, CH_zeroed)[0..8] equals the
    //           bytes lifted from session_id[8..16] in the live capture.
    return error.SkipZigTest;
}
