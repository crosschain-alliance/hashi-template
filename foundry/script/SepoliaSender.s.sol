// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import { SepoliaSender } from "../src/SepoliaSender.sol";

contract SenderScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address[] memory reporters = new address[](1);
        reporters[0] = 0x5574Af502113a5cc164185f0d9091bC352f1D1ec;
        address[] memory adapters = new address[](1);
        adapters[0] = 0x746dfa0251A31e587E97bBe0c58ED67A343280Df;
        vm.startBroadcast(deployerPrivateKey);
        SepoliaSender sender = new SepoliaSender(0x21eAB033C7D2DF6A67AeF6C5Bda9A7F151eB9f52, 1, reporters, adapters);
        vm.stopBroadcast();
    }
}
