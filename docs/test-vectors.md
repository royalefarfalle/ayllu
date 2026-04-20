# Test vectors for REALITY / Xray v25.x wire-compat

This document captures the procedures we use to generate known-answer-test
(KAT) vectors against live reference implementations. The actual vectors live
in-tree as fixture files (e.g. `camouflage/tls/xray_v25_vectors.zig`); this
file explains how to produce new captures so the fixtures stay reproducible.

## Xray v25.x ClientHello → AuthKey

**Why**: we need byte-exact confidence that `xray_wire.computeAuthMac` and
`xray_wire.verifyClientHello` match Xray's wire format before we ship a server
that third-party Xray clients can reach.

**Prereq**: a self-hosted Xray v25.x reachable on a loopback interface, built
from source so the `private_key` / `short_id` you configured at boot is the
same one you use to derive the expected `auth_key` offline.

### Capture procedure

1. Pin the Xray version:

   ```sh
   git clone https://github.com/XTLS/Xray-core.git && cd Xray-core
   git checkout v25.x.y         # match whatever is running in the wild
   go build -o xray ./main
   ```

2. Generate a REALITY keypair and note the base64url-no-pad encoded private
   key plus a short_id:

   ```sh
   ./xray x25519                  # prints PrivateKey= and Password=
   openssl rand -hex 8            # short_id
   ```

3. Start the Xray server with a minimal REALITY inbound (`server.json`):

   ```jsonc
   {
     "inbounds": [{
       "listen": "127.0.0.1", "port": 11443, "protocol": "vless",
       "settings": { "clients": [{ "id": "<uuid>" }], "decryption": "none" },
       "streamSettings": {
         "network": "tcp",
         "security": "reality",
         "realitySettings": {
           "dest": "www.microsoft.com:443",
           "serverNames": ["www.microsoft.com"],
           "privateKey": "<from x25519>",
           "shortIds": ["<from openssl>"]
         }
       }
     }]
   }
   ```

4. Start Xray client (`xray-client -c client.json`) with a matching Reality
   configuration pointing to `127.0.0.1:11443`.

5. Capture the ClientHello record:

   ```sh
   sudo tshark -i lo0 -f 'tcp port 11443' -w xray_v25.pcap
   ```

   Trigger a single connection from the client, then stop tshark.

6. Extract the raw ClientHello bytes (the whole TLS record — header + body —
   from offset 0 of the first handshake record sent by the client):

   ```sh
   tshark -r xray_v25.pcap \
     -Y 'tls.handshake.type == 1' \
     -T fields -e tls.record \
     | head -1 | xxd -r -p > ch.bin
   ```

   `ch.bin` should be 5 + N bytes. The TLS record header occupies the first
   five; the rest is the handshake message.

### Offline derivation

Feed the capture back through our own code to produce the expected `auth_key`:

```zig
const raw_record = @embedFile("ch.bin");
const ch_body = raw_record[9..]; // skip 5 (record hdr) + 4 (handshake hdr)

var scratch: [4]?[]const u8 = @splat(null);
const hello = try client_hello.parse(ch_body, &scratch);
const verified = try xray_wire.verifyClientHello(cfg, hello, now_ms);

// verified.material.auth_key is the expected AuthKey.
// xray_wire.computeAuthMac(verified.material.auth_key, ch_body)[0..8]
// should equal bytes 8..16 of hello.session_id.
```

If either comparison fails, either the code is wrong or the Xray version we
captured from differs from what we target — document the mismatch in this
file before committing new vectors.

### Landing the vectors

1. Drop the raw bytes into `camouflage/tls/testdata/xray_v25_ch.bin` (create
   the dir; `@embedFile` picks it up).
2. Replace the `return error.SkipZigTest` lines in
   `camouflage/tls/xray_v25_vectors.zig` with concrete assertions over the
   embedded bytes.
3. Record the captured `unix_ms`, `short_id`, and `private_key` as consts
   inside the test so future maintainers can reproduce without reading this
   doc.

## JA4_s cover-host parity (C6)

Stub section: populated when C6 lands JA4 parity fixtures. Captures pin the
expected JA4_s hash for three cover hosts so our forged ServerHello produces
the same fingerprint as the real server.
