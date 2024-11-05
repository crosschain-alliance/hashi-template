// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IYaho {
    function dispatchMessageToAdapters(
        uint256 targetChainId,
        uint256 threshold,
        address targetAddress,
        bytes memory data,
        address[] memory reporters,
        address[] memory adapters
    ) external;
}

contract SepoliaSender {
    IYaho public yaho;
    uint256 public threshold;
    address[] public reporters;
    address[] public adapters;

    constructor(address _yahoAddress, uint256 _threshold, address[] memory _reporters, address[] memory _adapters) {
        yaho = IYaho(_yahoAddress);
        threshold = _threshold;
        reporters = _reporters;
        adapters = _adapters;
    }

    // Function to send a cross-chain message to Chiado
    function sendMessageToChiado(
        uint256 targetChainId,
        address targetAddress,
        string memory _message
    ) public {
        bytes memory data = abi.encode(_message);
        yaho.dispatchMessageToAdapters(targetChainId, threshold, targetAddress, data, reporters, adapters);
    }
}