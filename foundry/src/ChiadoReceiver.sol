// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ChiadoReceiver {
    address public constant YARU = 0xBA9165973963a6E5608f03b9648c34A737E48f68;/* address of Yaru on Chiado */
    uint256 public constant SOURCE_CHAIN_ID = 11155111;/* chain ID of Sepolia */ 
    uint256 public constant EXPECTED_THRESHOLD = 1;/* expected threshold, should be equal to `threshold` from SepoliaSender */
    address public SOURCE_SENDER_ADDRESS;/* address of the Sepolia sender */
    bytes32 public ADAPTERS_HASH;

    string public lastReceivedMessage;
    
    constructor(address sourceSender, address[] memory adapters){
        SOURCE_SENDER_ADDRESS = sourceSender;
        ADAPTERS_HASH = keccak256(abi.encodePacked(adapters));
    }

    // Function that gets triggered when the message is relayed
    function onMessage(
        uint256, /*messageId*/
        uint256 chainId,
        address sender,
        uint256 threshold,
        address[] memory adapters,
        bytes memory data
    ) external returns (bytes memory) {
        require(
            msg.sender == YARU &&
            chainId == SOURCE_CHAIN_ID &&
            sender == SOURCE_SENDER_ADDRESS &&
            threshold == EXPECTED_THRESHOLD &&
            keccak256(abi.encodePacked(adapters)) == ADAPTERS_HASH,
            "Invalid message or sender"
        );

        // Decode the message and store it
        (string memory message) = abi.decode(data, (string));
        lastReceivedMessage = message;

        return "";
    }
}