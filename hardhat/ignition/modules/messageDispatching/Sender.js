// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
require("dotenv").config();

// Yaho address on source chain source: https://crosschain-alliance.gitbook.io/hashi/deployments/blockchains
const YAHO_ADDRESS = process.env.YAHO_ADDRESS;
const THRESHOLD = process.env.THRESHOLD; // threshold that has to meet by adapters on target chain, 0 < threshold <= # of adapters on target chain
// reporter on source chain, source: https://crosschain-alliance.gitbook.io/hashi/deployments/oracles#reporter
const REPORTERS = [process.env.REPORTERS];
// adapter on target chain, source: https://crosschain-alliance.gitbook.io/hashi/deployments/oracles#adapter
const ADAPTERS = [process.env.ADAPTERS];

module.exports = buildModule("SenderModule", (m) => {
  const yahoAddress = m.getParameter("yahoAddress", YAHO_ADDRESS);
  const threshold = m.getParameter("threshold", THRESHOLD);
  const reporters = m.getParameter("reporters", REPORTERS);
  const adapters = m.getParameter("adapters", ADAPTERS);

  const sender = m.contract("Sender", [
    yahoAddress,
    threshold,
    reporters,
    adapters,
  ]);

  return { sender };
});
