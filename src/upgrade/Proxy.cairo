%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.starknet.common.syscalls import library_call, library_call_l1_handler

from src.upgrade.Upgradable import _get_implementation, _set_implementation
from account.library import PluginAccount

/////////////////////
// CONSTRUCTOR
/////////////////////

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    implementation: felt, selector: felt, calldata_len: felt, calldata: felt*
) {
    _set_implementation(implementation);
    library_call(
        class_hash=implementation,
        function_selector=selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return ();
}

/////////////////////
// EXTERNAL FUNCTIONS
/////////////////////

@external
@raw_input
@raw_output
func __default__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    selector: felt, calldata_size: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let (implementation) = _get_implementation();

    let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=implementation,
        function_selector=selector,
        calldata_size=calldata_size,
        calldata=calldata,
    );
    return (retdata_size=retdata_size, retdata=retdata);
}

@l1_handler
@raw_input
func __l1_default__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    selector: felt, calldata_size: felt, calldata: felt*
) {
    let (implementation) = _get_implementation();

    library_call_l1_handler(
        class_hash=implementation,
        function_selector=selector,
        calldata_size=calldata_size,
        calldata=calldata,
    );
    return ();
}

@external
func __validate_deploy__{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    range_check_ptr
} (
    class_hash: felt,
    contract_address_salt: felt,
    implementation: felt,
    selector: felt,
    calldata_len: felt,
    calldata: felt*
) {
    PluginAccount.validate_deploy();
    return ();
}

/////////////////////
// VIEW FUNCTIONS
/////////////////////

@view
func get_implementation{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    implementation: felt
) {
    let (implementation) = _get_implementation();
    return (implementation=implementation);
}
