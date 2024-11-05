// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import { MockERC20Prover } from "../../src/stateVerifying/MockERC20Prover.sol";

contract MockERC20ProverScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address hashiProver = vm.envAddress("HASHI_PROVER_ADDRESS");
        address erc20Contract = vm.envAddress("MOCK_ERC20_ADDRESS");
        uint256 chainID = vm.envUint("CHAIN_ID");
        vm.startBroadcast(deployerPrivateKey);
        MockERC20Prover mockERC20Prover = new MockERC20Prover(hashiProver,erc20Contract,chainID);
        vm.stopBroadcast();
    }
}