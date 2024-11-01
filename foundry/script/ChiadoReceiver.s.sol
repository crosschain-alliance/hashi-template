// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import { ChiadoReceiver } from "../src/ChiadoReceiver.sol";

contract SenderScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address sourceSender;  // replace with address of SepoliaSender
        address[] memory adapters = new address[](1);
        adapters[0] = 0x746dfa0251A31e587E97bBe0c58ED67A343280Df;
        
        vm.startBroadcast(deployerPrivateKey);
        ChiadoReceiver receiver = new ChiadoReceiver(sourceSender, adapters);
        vm.stopBroadcast();
    }
}
