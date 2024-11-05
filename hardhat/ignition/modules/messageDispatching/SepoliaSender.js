// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

// Yaho address on Sepolia, source: https://crosschain-alliance.gitbook.io/hashi/deployments/blockchains
const YAHO_ADDRESS = "0x21eAB033C7D2DF6A67AeF6C5Bda9A7F151eB9f52";
const THRESHOLD = 1; // threshold that has to meet by adapters on Chiado, 0 < threshold <= # of adapters on Chiado
// LayerZzero reporter on Sepolia, source: https://crosschain-alliance.gitbook.io/hashi/deployments/oracles#reporter
const REPORTERS = ["0x5574Af502113a5cc164185f0d9091bC352f1D1ec"];
// LayerZero adapter on Chiado, source: https://crosschain-alliance.gitbook.io/hashi/deployments/oracles#adapter
const ADAPTERS = ["0x746dfa0251A31e587E97bBe0c58ED67A343280Df"];

module.exports = buildModule("SepoliaSenderModule", (m) => {
  const yahoAddress = m.getParameter("yahoAddress", YAHO_ADDRESS);
  const threshold = m.getParameter("threshold", THRESHOLD);
  const reporters = m.getParameter("reporters", REPORTERS);
  const adapters = m.getParameter("adapters", ADAPTERS);

  const sepoliaSender = m.contract("SepoliaSender", [
    yahoAddress,
    threshold,
    reporters,
    adapters,
  ]);

  return { sepoliaSender };
});
