## Hashi template - Foundry edition

This folder demonstrates a basic use case for Hashi using Foundry. For more details about Foundry, see their [documentation](https://book.getfoundry.sh/getting-started/first-steps).

# Develoment

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

Configure parameters in .env. Run script

```shell
$ forge script script/$ContractName.s.sol: --rpc-url <your_rpc_url> --private-key <your_private_key> --broadcast --verify
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
