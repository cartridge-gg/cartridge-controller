// SPDX-License-Identifier: MIT

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.starknet.common.syscalls import get_tx_info, get_contract_address
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.ec import EcPoint

from src.controller.library import Controller

struct CallArray {
    to: felt,
    selector: felt,
    data_offset: felt,
    data_len: felt,
}

@event
func controller_init(account: felt, admin_key: EcPoint, device_key: felt) {
}

@event
func controller_add_device_key(device_key: felt) {
}

@event
func controller_remove_device_key(device_key: felt) {
}

@external
func initialize{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    plugin_data_len: felt, plugin_data: felt*
) {
    with_attr error_message("Controller: invalid initilize data") {
        assert plugin_data_len = 7;
    }

    let admin_key = EcPoint(BigInt3(plugin_data[0], plugin_data[1], plugin_data[2]), BigInt3(plugin_data[3], plugin_data[4], plugin_data[5]));
    Controller.initializer(admin_key, plugin_data[6]);

    let (self) = get_contract_address();
    controller_init.emit(self, admin_key, plugin_data[6]);
    return ();
}

//
// Getters
//

@view
func is_public_key{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    public_key: felt
) -> (res: felt) {
    let (res) = Controller.is_public_key(public_key);
    return (res=res);
}

//
// Setters
//

@external
func add_device_key{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_device_key: felt
) {
    Controller.add_device_key(new_device_key);
    controller_add_device_key.emit(new_device_key);
    return ();
}

@external
func remove_device_key{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    device_key: felt
) {
    Controller.remove_device_key(device_key);
    controller_remove_device_key.emit(device_key);
    return ();
}

//
// Business logic
//

@view
func is_valid_signature{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
}(hash: felt, signature_len: felt, signature: felt*) -> (is_valid: felt) {
    let (is_valid) = Controller.is_valid_signature(hash, signature_len, signature);
    return (is_valid=is_valid);
}

@external
func validate{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
}(
    plugin_data_len: felt,
    plugin_data: felt*,
    call_array_len: felt,
    call_array: CallArray*,
    calldata_len: felt,
    calldata: felt*,
) {
    let (tx_info) = get_tx_info();
    is_valid_signature(tx_info.transaction_hash, plugin_data_len, plugin_data);
    return ();
}
