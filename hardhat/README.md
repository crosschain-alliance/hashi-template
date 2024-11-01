# Hashi template - Hardhat edition

This folder demonstrates a basic use case for Hashi using Hardhat. For more details about Hardhat, see their [documentation](https://hardhat.org/docs).

# Development

## Setup

Install dependencies:

```
npm install
```

## Spin up a local node

```
npx hardhat node
```

## Deployment

Copy the example environment file and configure it:

```
cp .env.example .env
```

Adjust deployment parameters in the .env file as needed. To add new networks, configure them in `hardhat.config.js`.

Deploy the contract:

```
npx hardhat ignition deploy ./ignition/modules/$ContractName.js --network $Network --verify
```
