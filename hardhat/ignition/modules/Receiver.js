// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
require("dotenv").config();

const YARU_ADDRESS = process.env.YARU_ADDRESS;
const SOURCE_CHAIN_ID = process.env.SOURCE_CHAIN_ID;
const EXPECTED_THRESHOLD = process.env.THRESHOLD;
const SOURCE_SENDER_ADDRESS = process.env.SENDER_ADDRESS; // The address of  Sender
// adapter on target chain, source: https://crosschain-alliance.gitbook.io/hashi/deployments/oracles#adapter
const ADAPTERS = [process.env.ADAPTERS];

module.exports = buildModule("ReceiverModule", (m) => {
  const yaruAddress = m.getParameter("yaruAddress", YARU_ADDRESS);
  const sourceChainID = m.getParameter("sourceChainID", SOURCE_CHAIN_ID);
  const expectedThreshold = m.getParameter(
    "expectedThreshold",
    EXPECTED_THRESHOLD
  );
  const sourceSenderAddress = m.getParameter(
    "sourceSenderAddress",
    SOURCE_SENDER_ADDRESS
  );
  const adapters = m.getParameter("adapters", ADAPTERS);

  const receiver = m.contract("Receiver", [
    yaruAddress,
    sourceChainID,
    expectedThreshold,
    sourceSenderAddress,
    adapters,
  ]);

  return { receiver };
});
