%lang starknet
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_secp.bigint import BigInt3

from src.controller.library import Controller

@external
func test_is_valid_webauthn_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
    }() {
    alloc_locals;
    local x0;
    local x1;
    local x2;
    local y0;
    local y1;
    local y2;

    local r0;
    local r1;
    local r2;
    local s0;
    local s1;
    local s2;
    local challenge_offset_len;
    local challenge_offset_rem;
    local challenge_len;
    local challenge_rem;
    local client_data_json_len;
    local client_data_json_rem;
    local authenticator_data_len;
    local authenticator_data_rem;

    local transaction_hash;
    let (local client_data_json_parts: felt*) = alloc();
    let (local authenticator_data_parts: felt*) = alloc();

    %{
        from tests.signer import WebauthnSigner
        signer = WebauthnSigner("localhost")
        (x0, x1, x2, y0, y1, y2) = signer.public_key
        (transaction_hash, r0, r1, r2, s0, s1, s2, challenge_offset_len, challenge_offset_rem, challenge_len, challenge_rem,
        client_data_json_len, client_data_json_rem, client_data_json_parts,
        authenticator_data_len, authenticator_data_rem, authenticator_data_parts) = signer.sign_transaction(123, [(1234, 'add_public_key', [0])], 0, 0)

        ids.x0 = x0
        ids.x1 = x1
        ids.x2 = x2
        ids.y0 = y0
        ids.y1 = y1
        ids.y2 = y2

        ids.r0 = r0
        ids.r1 = r1
        ids.r2 = r2
        ids.s0 = s0
        ids.s1 = s1
        ids.s2 = s2
        ids.challenge_offset_len = challenge_offset_len
        ids.challenge_offset_rem = challenge_offset_rem
        ids.challenge_len = challenge_len
        ids.challenge_rem = challenge_rem
        ids.client_data_json_len = client_data_json_len
        ids.client_data_json_rem = client_data_json_rem
        ids.authenticator_data_len = authenticator_data_len
        ids.authenticator_data_rem = authenticator_data_rem

        ids.transaction_hash = transaction_hash
        segments.write_arg(ids.client_data_json_parts, client_data_json_parts)
        segments.write_arg(ids.authenticator_data_parts, authenticator_data_parts)
    %}

    Controller.is_valid_webauth_signature(
        EcPoint(BigInt3(x0, x1, x2), BigInt3(y0, y1, y2)), transaction_hash,
        BigInt3(r0, r1, r2),
        BigInt3(s0, s1, s2),
        challenge_offset_len,
        challenge_offset_rem,
        client_data_json_len,
        client_data_json_rem,
        client_data_json_parts,
        authenticator_data_len,
        authenticator_data_rem,
        authenticator_data_parts);

    return ();
}
