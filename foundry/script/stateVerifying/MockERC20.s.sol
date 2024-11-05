// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import { MockERC20 } from "../../src/stateVerifying/MockERC20.sol";

contract MockERC20Script is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
  
        vm.startBroadcast(deployerPrivateKey);
        MockERC20 mockERC20 = new MockERC20("MockERC20Token","MER",1e25);
        vm.stopBroadcast();
    }
}