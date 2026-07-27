# PACE implementation design

Status: approved, in implementation on branch `pace`.

## Goal

Implement Password Authenticated Connection Establishment (ICAO 9303 part 11 §4.4) so passauf
can read PACE-capable and PACE-only documents, covering a broad range of the algorithm
combinations documents actually use, not a single hardcoded variant.

## Scope

Supported:

- Mappings: Generic Mapping (GM), Integrated Mapping (IM)
- Key agreement: ECDH and DH
- Ciphers: 3DES-CBC-CBC, AES-CBC-CMAC-128/192/256
- Passwords: MRZ and CAN
- Standardized domain parameters: 0, 1, 2 (MODP), 12, 13, 15, 16, 18 (ECP)

Out of scope:

- Chip Authentication Mapping (CAM). Recognized in the OID table so we can report it precisely,
  but not performed.
- Domain parameter IDs 8, 9, 10, 11, 14, 17. These are NIST P-192/P-224 and BrainpoolP192r1/
  P224r1/P320r1/P512r1, none of which have a usable Rust crate. Implementing them would mean
  hand-rolling curve arithmetic, which is a correctness and side-channel risk we are not taking.
  ID 10 (NIST P-224) additionally cannot be used with Integrated Mapping at all per the spec.
- Explicit (non-standardized) domain parameters carried in PACEDomainParameterInfo.
- Terminal Authentication, Chip Authentication, and the 0x7F4C CHAT data object.

## Forced dependency changes

The pre-release pins in `Cargo.toml` cannot survive contact with `aes`.

`aes 0.9.2` depends on `cipher 0.5.2`, whereas `des 0.9.0-pre.2` and `cbc 0.2.0-pre.2` depend on
`cipher 0.5.0-pre.7`. Cargo compiles both, so `cbc::Encryptor<Aes128>` would fail to typecheck
against a `cipher` different from the one `cbc` was built with. The entire RustCrypto stack has
since gone stable (`des 0.9.0`, `cbc 0.2.1`, `sha1 0.11.0`, `retail-mac 0.1.0`), and the all-stable
set was verified to resolve on a single `cipher 0.5.2` / `digest 0.11.3` / `elliptic-curve 0.14.1`.

Separately, `rand 0.9` uses `rand_core 0.9` while `elliptic-curve 0.14` uses `rand_core 0.10`, so
`rand` is bumped to 0.10 to keep one RNG trait for ephemeral key generation.

This lets the "these are pending cipher/digest release" comment block come out of `Cargo.toml`.

## Architecture

```
src/pace/mod.rs          do_pace_authentication(), GENERAL AUTHENTICATE chaining
src/pace/oids.rs         PACE OID -> {key agreement, mapping, cipher}
src/pace/domain.rs       standardized domain parameter tables
src/pace/password.rs     K_pi derivation from MRZ / CAN
src/pace/mapping.rs      GM; IM's R_p() PRF and Appendix B.2 point encoding
src/pace/ecdh.rs         curve-generic ECDH, parameter ID dispatch
src/pace/dh.rs           MODP group operations
src/secure_messaging.rs  SecureMessaging, replacing the (ssc, ks_enc, ks_mac) triple
src/types/ef_cardaccess.rs  SecurityInfos parsing (replaces commented-out sketches)
src/iso7816.rs           + apdu_mse_set_at, apdu_general_authenticate
```

### SecureMessaging

PACE breaks three assumptions currently baked into `iso7816.rs`: that the SSC is a `u64`, that the
block size is 8, and that the MAC is Retail-MAC. Rather than widen the existing three-parameter
convention, a single struct owns the session state:

```rust
pub struct SecureMessaging {
    algo: SmAlgorithm,   // Tdes | Aes128 | Aes192 | Aes256
    ks_enc: Vec<u8>,
    ks_mac: Vec<u8>,
    ssc: Vec<u8>,        // 8 bytes for 3DES, 16 for AES
}
```

with `encrypt`, `decrypt`, `mac`, `bump_ssc` and `block_size`. For AES the CBC IV is
`AES-ECB(ks_enc, ssc)` rather than all-zeroes, the CMAC is truncated to 8 bytes, and padding
method 2 operates on a 16-byte block.

`bac_secure_serialize` becomes `secure_serialize(&mut sm)`. BAC constructs the `Tdes` variant and
must keep working unchanged; PACE constructs whichever variant its OID names. This replaces the
`&mut ssc, &ks_enc, &ks_mac` triple in `secure_exchange`, `select_and_read_file`,
`parse_secure_rapdu`, `helpers::secure_read_file{,_by_name}` and `main.rs`.

### Curve genericity

GM, IM and the key agreement are written once over `C: CurveArithmetic + PrimeCurveParams`, with a
`match` on the parameter ID at the dispatch point selecting `p256` / `p384` / `p521` / `bp256` /
`bp384`.

Integrated Mapping needs base-field arithmetic (modular inversion and exponentiation mod p) that
those crates do not expose publicly. That math is done in `crypto-bigint` `BoxedMontyForm`, which
is curve-generic anyway; the resulting affine `(x, y)` is then handed to the curve crate as a SEC1
`04 || X || Y` encoding via `FromEncodedPoint`, which validates it is on the curve. The cofactor is
1 for every supported curve, so Appendix B.2 step 10 is a no-op.

## Protocol flow

1. Read and parse `EF.CardAccess`, pick a supported `PACEInfo`.
2. `MSE:Set AT` (INS 0x22, P1P2 0xC1A4) with 0x80 = protocol OID, 0x83 = password reference
   (1 = MRZ, 2 = CAN), and 0x84 = parameter ID when domain parameters are ambiguous.
3. `GENERAL AUTHENTICATE` chain (INS 0x86, P1P2 0x0000, data wrapped in 0x7C, CLA 0x10 on every
   command but the last):
   - Step 1: empty request, response 0x80 = encrypted nonce. Decrypt with K_pi (CBC, IV = 0) to
     get s.
   - Step 2: 0x81 mapping data out, 0x82 mapping data back. For GM this is an ephemeral public key
     pair and yields `G_hat = s*G + H` (ECDH) or `g_hat = g^s * h` (DH). For IM the terminal sends
     nonce t and the response 0x82 is empty.
   - Step 3: 0x83 our ephemeral public key over the mapped generator, 0x84 theirs. Shared secret K
     from the key agreement, then `KS_enc = KDF(K,1)`, `KS_mac = KDF(K,2)`.
   - Step 4: 0x85 = T_IFD, 0x86 = T_IC. The token is a MAC under KS_mac over the public key data
     object of §9.4.5 holding the MSE:Set AT OID and the *peer's* ephemeral public key, with domain
     parameters excluded. Verify T_IC.
4. Hand back a `SecureMessaging` with SSC starting at 0.

KDF uses SHA-1 for 3DES and AES-128, SHA-256 for AES-192 and AES-256. K_pi is `KDF(K, 3)`, where K
is `SHA-1(docnum+cd || dob+cd || doe+cd)` for MRZ and the raw ASCII bytes for CAN.

## Testing

`standards/9303_p11_cons_en.pdf` carries complete worked examples with intermediate values, which
become unit tests asserting every step, requiring no hardware:

- Appendix G.1: ECDH GM, BrainpoolP256r1, AES-128
- Appendix G.2: DH GM, 1024-bit MODP, 3DES
- Appendix H: Integrated Mapping

Plus unit tests for `EF.CardAccess` parsing and the OID table. BAC regression is covered by the
existing behaviour continuing to work after the `SecureMessaging` migration. Confirmation against
real documents (a BAC-only, a BAC+PACE and a PACE-only) is done by hand afterwards.

## Documentation

README gains a support matrix listing every mapping, key agreement, cipher and all 20 standardized
domain parameter IDs, marking what works and giving the reason for what does not. The README claims
that PACE is unimplemented and that `--can` is unusable are removed, and infodump.md's PACE
terminology entry is filled in. At runtime, an unsupported variant produces a message naming the
specific OID or parameter ID rather than a bare panic.
