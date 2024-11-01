// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

const SOURCE_SENDER_ADDRESS = "0x10eDb85A4684C5a28012ec3c057051DFCC30b35a"; // The address of Sepolia Sender
// LayerZero adapter on Chiado, source: https://crosschain-alliance.gitbook.io/hashi/deployments/oracles#adapter
const ADAPTERS = ["0x746dfa0251A31e587E97bBe0c58ED67A343280Df"];

module.exports = buildModule("chiadoReceiverModule", (m) => {
  const sourceSenderAddress = m.getParameter(
    "sourceSenderAddress",
    SOURCE_SENDER_ADDRESS
  );
  const adapters = m.getParameter("adapters", ADAPTERS);

  const chiadoReceiver = m.contract("ChiadoReceiver", [
    sourceSenderAddress,
    adapters,
  ]);

  return { chiadoReceiver };
});
