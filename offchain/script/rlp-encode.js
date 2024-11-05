import { RLP } from "@ethereumjs/rlp";
import { decodeAbiParameters, parseAbiParameters } from "viem";

// This script illustrates how to get the rlp encoded event data that can be used to compare with the return result from HashiProver.verifyForeignEvent function
function encodeEventData(contractAddress, topics, data) {
  // Convert hex strings to Buffers
  const addressBuffer = Buffer.from(contractAddress.slice(2), "hex");
  const topicBuffers = topics.map((topic) =>
    Buffer.from(topic.slice(2), "hex")
  );
  const dataBuffer = Buffer.from(data.slice(2), "hex");

  // Create the event structure
  const event = [addressBuffer, topicBuffers, dataBuffer];

  // RLP encode the event
  const encodedEvent = RLP.encode(event);

  // Calculate the data length (length of the RLP encoded event)
  const dataLength = encodedEvent.length;

  // Create the data length buffer (32 bytes, big-endian)
  const dataLengthBuffer = Buffer.alloc(32);
  dataLengthBuffer.writeUInt32BE(dataLength, 28);

  // Create the length buffer (always 32 bytes for this structure)
  const lengthBuffer = Buffer.alloc(32);
  lengthBuffer.writeUInt32BE(32, 28);

  // Concatenate all parts
  let finalEncoded = Buffer.concat([
    lengthBuffer,
    dataLengthBuffer,
    encodedEvent,
  ]);

  // Add padding to make the total length a multiple of 32 bytes
  const paddingLength = 32 - (finalEncoded.length % 32);
  if (paddingLength < 32) {
    const padding = Buffer.alloc(paddingLength).fill(0);
    finalEncoded = Buffer.concat([finalEncoded, padding]);
  }

  // Return a bytes encoded rlp data
  return {
    finalEncoded: "0x" + finalEncoded.toString("hex"),
    length: 32,
    dataLength: dataLength,
    totalLength: finalEncoded.length,
  };
}

// Dev: replace the event data
const contractAddress = "0xB3b231614882E8ffa69eB7E37E845060456fF21b";
const topics = [
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // topic 0
  "0x00000000000000000000000067E5855Aa4D5786c086b7FC6B4203a5Ea50E93F8", // from
  "0x0000000000000000000000008a11DA83262eAF7c2262A65C585767E5BE8dD904", // to
];
const data =
  "0x0000000000000000000000000000000000000000000000008ac7230489e80000"; // value

const rlpEncodedData = encodeEventData(contractAddress, topics, data);

// Get this value as expectedRlpEncodedEvent argument in the MockERC20Prover.verifyTransferEvent
const bytesDecoded = decodeAbiParameters(
  parseAbiParameters("bytes memory x"),
  rlpEncodedData.finalEncoded
);

console.log("RLP Encoded Data", bytesDecoded);
