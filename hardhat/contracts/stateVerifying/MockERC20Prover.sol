// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { HashiProver } from "./HashiProver.sol";

contract MockERC20Prover {

    event totalSupplyFromERC20(uint256 indexed chainID, address indexed erc20Contract, uint256 indexed totalSupply);

    event TransferEventVerified(uint256 indexed chainID, bytes rlpEncodedEvent);

    HashiProver public hashiProver;
    address public erc20Contract;
    uint256 public chainID;

    constructor(address hashiProver_, address erc20Contract_, uint256 chainID_) {
        hashiProver = HashiProver(hashiProver_);
        erc20Contract = erc20Contract_;
        chainID = chainID_;
    }
    function readTotalSupply(HashiProver.AccountAndStorageProof calldata proof) external {
        require(proof.chainId == chainID, "Invalid chain id"); 
        require(proof.account == erc20Contract, "Invalid account");
        require(proof.storageKeys.length == 1 && proof.storageKeys[0] == bytes32(uint256(0x02)), "Invalid storage key"); // storage key of total supply: 0x0b
        uint256 totalSupply;
        bytes memory totalSupplyinBytes = hashiProver.verifyForeignStorage(proof)[0];
        
        assembly {
            let length := mload(totalSupplyinBytes)
            let data := mload(add(totalSupplyinBytes, 0x20))
            let padSize := mul(sub(0x20,length),8)
            totalSupply := shr(padSize,data)
        }

        emit totalSupplyFromERC20(proof.chainId,proof.account, totalSupply);
        // TODO: Define your logic here

    }

    function verifyTransferEvent(HashiProver.ReceiptProof calldata proof, bytes memory expectedRlpEncodedEvent) external {
        require(proof.chainId == chainID, "Invalid chain id"); 

        bytes memory rlpEncodedEvent = hashiProver.verifyForeignEvent(proof);

        require(keccak256(rlpEncodedEvent) == keccak256(expectedRlpEncodedEvent), "invalid event");
        emit TransferEventVerified(proof.chainId , rlpEncodedEvent);

        // TODO: Define your logic here

    }
}