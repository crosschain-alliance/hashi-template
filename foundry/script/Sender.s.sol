// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import { Sender } from "../src/Sender.sol";

contract SenderScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address yahoAddress = vm.envAddress("YAHO_ADDRESS");
        uint256 threshold = vm.envUint("THRESHOLD");
        address reporter = vm.envAddress("REPORTERS");
        address adapter = vm.envAddress("ADAPTERS");
        address[] memory reporters = new address[](1);
        reporters[0] = reporter;
        address[] memory adapters = new address[](1);
        adapters[0] = adapter;


        
        vm.startBroadcast(deployerPrivateKey);
        Sender sender = new Sender(yahoAddress, threshold, reporters, adapters);
        vm.stopBroadcast();
    }
}
