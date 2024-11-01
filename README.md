# Hashi template

This repository serves as a template for developers to kickstart a Hashi project using Hardhat/Foundry.

This template includes basic contracts and deployment scripts to set up a Hashi-based project quickly. To follow along, refer to `Quick Start` tutorial in the [Hashi documentation](https://crosschain-alliance.gitbook.io/hashi/getting-started/quick-start).

## Contract Overview

1. `Sender`: contract from source chain that calls `Yaho` to dispatch message on target chain. Developers can define the logic in their sender contract from source chain, i.e. `SepoliaSender.sol`.
2. `Receiver`: contract on target chain that receives callback from `Yaru` and execute further logic is threshold is met by oracles (adapters on target chain). Developers can define the logic in their receiver contract on target chain, i.e. `ChiadoReceiver.sol`.

To learn more about the key contracts in Hashi, check out [Key Contracts in Hashi Documentation](https://crosschain-alliance.gitbook.io/hashi/api-and-smart-contracts/key-contracts).

## Deployment

To get the deployment addresses of Yaho and Yaru, check out [here](https://crosschain-alliance.gitbook.io/hashi/deployments/blockchains). Note that `Yaho` is deployed on source chain, and `Yaru` is deployed on target/destination chain with respect to the source chain.

To get the oracle(reporter & adapter) addresses, check out [here](https://crosschain-alliance.gitbook.io/hashi/deployments/oracles). At the moment, [LayerZero](https://layerzero.network/) covers most of the networks that are supported by Hashi.

# Structure

1. Hardhat: Template using Hardhat. Consist of contracts, deploy scripts, and configuration.
2. Foundry: Template using Foundry. Consist of contracts, deploy scripts, and configuration.

# Reference

1. Hashi documentation: https://crosschain-alliance.gitbook.io/hashi
2. Hashi repository: https://github.com/gnosis/hashi/
