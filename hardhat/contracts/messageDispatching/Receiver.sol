// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Receiver {
    /// @dev Yaru contract on the receiver chain w.r.t the Yaho's source chain
    address public YARU;  
    /// @dev Source chain ID that comply with EIP 155
    uint256 public SOURCE_CHAIN_ID;
    /// @dev Expected threshold to be met by the adapters
    uint256 public EXPECTED_THRESHOLD;
    /// @dev Sender contract address from source chain
    address public SOURCE_SENDER_ADDRESS;
    /// @dev hash of adapters address 
    bytes32 public ADAPTERS_HASH;
    /// @dev message that is last received from sender contract's sendMessageToTarget function
    string public lastReceivedMessage;
    

    constructor(address yaru, uint256 sourceChainId, uint256 expectedThreshold, address sourceSender, address[] memory adapters){
        YARU = yaru;
        SOURCE_CHAIN_ID = sourceChainId;
        EXPECTED_THRESHOLD = expectedThreshold;
        SOURCE_SENDER_ADDRESS = sourceSender;
        ADAPTERS_HASH = keccak256(abi.encodePacked(adapters));
    }

    /// @dev Function that gets triggered when the message is relayed, called by Yaru contract
    /// @param chainId chainId of the chain where message is sending from
    /// @param sender sender contract
    /// @param threshold threshold of the message that should be met by adapters
    /// @param adapters an array of adapters to check the threshold with
    /// @param data abi-encoded message
    /// @return 
    function onMessage(
        uint256, /*messageId*/
        uint256 chainId,
        address sender,
        uint256 threshold,
        address[] memory adapters,
        bytes memory data
    ) external returns (bytes memory) {
        require(msg.sender == YARU, "only called by Yaru");
        require(chainId == SOURCE_CHAIN_ID, "invalid source chain ID");
        require(threshold == EXPECTED_THRESHOLD, "invalid number of threshold");
        require(sender == SOURCE_SENDER_ADDRESS, "invalid sender address from source chain");
        require( keccak256(abi.encodePacked(adapters)) == ADAPTERS_HASH, "invalid adapters hash");
    
        // Decode the message and store it
        (string memory message) = abi.decode(data, (string));
        lastReceivedMessage = message;

        return "";
    }
}