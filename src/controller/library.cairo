%lang starknet

from starkware.starknet.common.syscalls import get_contract_address
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.math import assert_not_zero, unsigned_div_rem, split_felt
from starkware.cairo.common.bitwise import bitwise_and
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_secp.bigint import BigInt3

from src.webauthn import Webauthn

//
// Storage
//

@storage_var
func Controller_device_key(pub: felt) -> (res: felt) {
}

@storage_var
func Controller_admin_key() -> (res: EcPoint) {
}

namespace Controller {
    //
    // Initializer
    //

    func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        admin_key: EcPoint, device_key: felt
    ) {
        let (existing_admin_key) = Controller_admin_key.read();
        with_attr error_message("Controller: account already initialized") {
            assert existing_admin_key.x.d0 = 0;
        }

        Controller_admin_key.write(admin_key);
        Controller_device_key.write(device_key, 1);

        return ();
    }

    //
    // Guards
    //

    func assert_only_self{syscall_ptr: felt*}() {
        let (self) = get_contract_address();
        let (caller) = get_caller_address();
        with_attr error_message("Account: caller is not this account") {
            assert self = caller;
        }
        return ();
    }

    //
    // Getters
    //

    func is_public_key{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        public_key: felt
    ) -> (res: felt) {
        let (res) = Controller_device_key.read(public_key);
        return (res=res);
    }

    //
    // Setters
    //

    func add_device_key{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        new_device_key: felt
    ) {
        assert_only_self();
        Controller_device_key.write(new_device_key, 1);
        return ();
    }

    func remove_device_key{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        device_key: felt
    ) {
        assert_only_self();

        with_attr error_message("Controller: invalid device key") {
            let (valid) = is_public_key(device_key);
            assert_not_zero(valid);
        }

        Controller_device_key.write(device_key, 0);
        return ();
    }

    //
    // Business logic
    //

    func is_valid_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
    }(hash: felt, signature_len: felt, signature: felt*) -> (is_valid: felt) {
        alloc_locals;

        if (signature[0] == 0) {
            let (admin_key) = Controller_admin_key.read();

            // Implementation expects the r, s components decomposed into their limbs.
            let sig_r0 = BigInt3(signature[1], signature[2], signature[3]);
            let sig_s0 = BigInt3(signature[4], signature[5], signature[6]);
            let challenge_offset_len = signature[7];
            let challenge_offset_rem = signature[8];
            let client_data_json_len = signature[9];
            let client_data_json_rem = signature[10];
            let client_data_json = signature + 11;
            let authenticator_data_len = signature[11 + client_data_json_len];
            let authenticator_data_rem = signature[12 + client_data_json_len];
            let authenticator_data = signature + 13 + client_data_json_len;

            let is_valid = is_valid_webauth_signature(admin_key, hash, sig_r0, sig_s0,
                challenge_offset_len, challenge_offset_rem,
                client_data_json_len, client_data_json_rem, client_data_json,
                authenticator_data_len, authenticator_data_rem, authenticator_data);

            return (is_valid=is_valid);
        } else {
            // This interface expects a signature pointer and length to make
            // no assumption about signature validation schemes.
            // But this implementation does, and it expects a (pub, sig_r, sig_s) tuple.
            let public_key = signature[0];
            let sig_r = signature[1];
            let sig_s = signature[2];

            let (is_pub) = Controller_device_key.read(public_key);

            assert_not_zero(is_pub);

            if (is_pub == TRUE) {
                verify_ecdsa_signature(
                    message=hash, public_key=public_key, signature_r=sig_r, signature_s=sig_s
                );
                return (is_valid=TRUE);
            }

            return (is_valid=FALSE);
        }
    }

    func is_valid_webauth_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
    }(
        key: EcPoint, hash: felt,
        sig_r0: BigInt3, sig_s0: BigInt3,
        challenge_offset_len: felt, challenge_offset_rem: felt,
        client_data_json_len: felt, client_data_json_rem: felt, client_data_json: felt*,
        authenticator_data_len: felt, authenticator_data_rem: felt, authenticator_data: felt*) -> felt {
        alloc_locals;

        let (local challenge: felt*) = alloc();

        let (high, low) = split_felt(hash);

        // Extract 24bit chunks which are then base64 encoded to 32bit words
        let (b0) = bitwise_and(low, 2 ** 16 - 1);

        let (q1, r1) = unsigned_div_rem(low, 2 ** 16);
        let (b1) = bitwise_and(q1, 2 ** 24 - 1);

        let (q2, r2) = unsigned_div_rem(q1, 2 ** 24);
        let (b2) = bitwise_and(q2, 2 ** 24 - 1);

        let (q3, r3) = unsigned_div_rem(q2, 2 ** 24);
        let (b3) = bitwise_and(q3, 2 ** 24 - 1);

        let (q4, r4) = unsigned_div_rem(q3, 2 ** 24);
        let (b4) = bitwise_and(q4, 2 ** 24 - 1);

        let (q5, r5) = unsigned_div_rem(q4, 2 ** 24);

        let (b50) = bitwise_and(high, 2 ** 8 - 1);
        let b5 = b50 * 2 ** 16 + q5;

        let (q6, r6) = unsigned_div_rem(high, 2 ** 8);
        let (b6) = bitwise_and(q6, 2 ** 24 - 1);

        let (q7, r7) = unsigned_div_rem(q6, 2 ** 24);
        let (b7) = bitwise_and(q7, 2 ** 24 - 1);

        let (q8, r8) = unsigned_div_rem(q7, 2 ** 24);
        let (b8) = bitwise_and(q8, 2 ** 24 - 1);

        let (q9, r9) = unsigned_div_rem(q8, 2 ** 24);
        let (b9) = bitwise_and(q9, 2 ** 24 - 1);

        let (q10, r10) = unsigned_div_rem(q9, 2 ** 24);
        let (b10) = bitwise_and(q10, 2 ** 24 - 1);

        assert challenge[0] = b10;
        assert challenge[1] = b9;
        assert challenge[2] = b8;
        assert challenge[3] = b7;
        assert challenge[4] = b6;
        assert challenge[5] = b5;
        assert challenge[6] = b4;
        assert challenge[7] = b3;
        assert challenge[8] = b2;
        assert challenge[9] = b1;
        assert challenge[10] = b0;

        let (local origin: felt*) = alloc();
        Webauthn.verify(
            key,
            sig_r0,
            sig_s0,
            0,
            0,
            challenge_offset_len,
            challenge_offset_rem,
            11,
            1,
            challenge,
            0,
            0,
            0,
            origin,
            client_data_json_len,
            client_data_json_rem,
            client_data_json,
            authenticator_data_len,
            authenticator_data_rem,
            authenticator_data,
        );

        return TRUE;
    }
}
