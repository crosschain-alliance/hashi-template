// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @dev https://github.com/gnosis/hashi/blob/main/packages/evm/contracts/interfaces/IYaho.sol
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

/// @title Sender contract from source chain
/// @notice Sender contract is called from source chain to dispatch message to target chain
contract Sender {
    IYaho public yaho;  // yaho address on source chain
    uint256 public threshold; // threshold that should be met by adapters from target chain, 0 < threshold < # of adapters on target chain
    address[] public reporters; // reporters from source chain
    address[] public adapters; // adapters from target chain

    constructor(address _yahoAddress, uint256 _threshold, address[] memory _reporters, address[] memory _adapters) {
        yaho = IYaho(_yahoAddress);
        threshold = _threshold;
        reporters = _reporters;
        adapters = _adapters;
    }

    /// @dev Function to send a cross-chain message to target chain
    /// @param targetChainId target chain ID that comply with EIP 155
    /// @param targetAddress receiver contract address on the target chain
    /// @param _message message to send
    function sendMessageToTarget(
        uint256 targetChainId,
        address targetAddress,
        string memory _message
    ) public {
        bytes memory data = abi.encode(_message);
        yaho.dispatchMessageToAdapters(targetChainId, threshold, targetAddress, data, reporters, adapters);
    }
}