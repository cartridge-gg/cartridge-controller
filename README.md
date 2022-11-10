# cairo-controller

Implementation of the Cartridge Controller plugin which supports using webauthn credentials for transaction validation.

## Testing

Add site packages to `PYTHONPATH` in order to use python scripts in protostar hints.
```sh
export PYTHONPATH=/Users/user/cairo_venv/lib/python3.9/site-packages
```

Run tests:
```
protostar test tests
```

## Deployment

```
protostar build

protostar declare ./build/account.json --network=testnet
protostar declare ./build/controller.json --network=testnet
protostar declare ./build/proxy.json --network=testnet
```

#### Existing deployments

Controller Class Hash: `0x0286a2ea79ee08506efcbc330efd2ae34e2f22b79ecd2fb9b86ce26d6a1dbece`

Account Class Hash:
`0x001c343436d77e564b39f88c13f77e9e45da188022a73e64580262b6ee1064a2`

Proxy Class Hash: `0x046ea2fdb36fb5fba24050ba137957f0107ad51b32da9300b3b302da952ecb4c`
