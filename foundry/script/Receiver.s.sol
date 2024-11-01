// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import { Receiver } from "../src/Receiver.sol";

contract SenderScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address yaruAddress = vm.envAddress("YARU_ADDRESS");
        uint256 expectedThreshold = vm.envUint("THRESHOLD");
        uint256 sourceChainId = vm.envUint("SOURCE_CHAIN_ID");
        address sourceSender = vm.envAddress("SENDER_ADDRESS");
        address adapter = vm.envAddress("ADAPTERS");
        address[] memory adapters = new address[](1);
        adapters[0] = adapter;
        
        vm.startBroadcast(deployerPrivateKey);
        Receiver receiver = new Receiver(yaruAddress, sourceChainId, expectedThreshold,sourceSender, adapters);
        vm.stopBroadcast();
    }
}
