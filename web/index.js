import initNoirC from "@noir-lang/noirc_abi";
import initACVM from "@noir-lang/acvm_js";
import acvm from "@noir-lang/acvm_js/web/acvm_js_bg.wasm?url";
import noirc from "@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url";

import { UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';

// Import JSON files statically
import compiledCircuit from '../circuits/target/anon_aadhaar.json';
import anonAadhaarInput from '../test-vectors/noir/anon_aadhaar_inputs.json';

// Initialize WASMs using paths resolved by Vite
await Promise.all([initACVM(fetch(acvm)), initNoirC(fetch(noirc))]);

const show = (id, content) => {
  const container = document.getElementById(id);
  // Clear previous logs in the container to prevent clutter, except for the h2
  while (container.childNodes.length > 1) {
    container.removeChild(container.lastChild);
  }
  container.appendChild(document.createTextNode(content));
  container.appendChild(document.createElement("br"));
};

const showAppend = (id, content) => {
  const container = document.getElementById(id);
  container.appendChild(document.createTextNode(content));
  container.appendChild(document.createElement("br"));
};


// Function to fetch the pre-compiled circuit
async function getCircuit() {
  // const response = await fetch('../circuit/target/circuit.json');
  // if (!response.ok) {
  //   throw new Error(`Failed to fetch circuit: ${response.statusText}`);
  // }
  // const compiledCircuit = await response.json();
  return compiledCircuit; // This is the circuit artifact (ACIR + ABI)
}

// Function to fetch the SRS
async function getSrs() {
  showAppend("logs", "Fetching SRS... ⏳");
  // Path relative to web/index.js: ../test-vectors/noir/circuit.srs (assuming generic name)
  const response = await fetch('../test-vectors/noir/circuit.srs');
  if (!response.ok) {
    showAppend("logs", `Failed to fetch SRS: ${response.statusText} 💔`);
    throw new Error(`Failed to fetch SRS: ${response.statusText}`);
  }
  const srsArrayBuffer = await response.arrayBuffer();
  showAppend("logs", "Fetched SRS... ✅");
  return new Uint8Array(srsArrayBuffer);
}

// Function to fetch the Anon Aadhaar input JSON
async function getAnonAadhaarInput() {
  showAppend("logs", "Fetching Anon Aadhaar input JSON... ⏳");
  // Path relative to web/index.js: ../test-vectors/noir/input.json (assuming generic name)
  // const response = await fetch('../test-vectors/noir/input.json');
  // if (!response.ok) {
  // showAppend("logs", `Failed to fetch Anon Aadhaar input JSON: ${response.statusText} 💔`);
  // throw new Error(`Failed to fetch Anon Aadhaar input JSON: ${response.statusText}`);
  // }
  // const anonAadhaarInput = await response.json();
  showAppend("logs", "Fetched Anon Aadhaar input JSON... ✅");
  return anonAadhaarInput;
}

document.getElementById("submit").addEventListener("click", async () => {
  try {
    show("logs", "Initializing...");
    show("results", ""); // Clear previous results

    const program = await getCircuit();
    showAppend("logs", "Fetched circuit... ✅");

    showAppend("logs", "Instantiating Noir... ⏳");
    const noir = new Noir(program); // Pass the fetched JSON (circuit artifact) directly
    showAppend("logs", "Instantiated Noir... ✅");

    showAppend("logs", "Instantiating Backend... ⏳");
    // program.bytecode is the ACIR (hex string or similar, as per Noir.js expectations)
    const backend = new UltraHonkBackend(program.bytecode);
    showAppend("logs", "Instantiated Backend... ✅");

    // // Load the custom SRS
    // const srsData = await getSrs();
    // showAppend("logs", "Initializing backend with SRS... ⏳");
    // await backend.initSrs(srsData); // Initialize backend with fetched SRS data
    // showAppend("logs", "Backend initialized with SRS... ✅");

    const inputs = await getAnonAadhaarInput();
    
    showAppend("logs", "Generating witness... ⏳");
    const witnessGenStart = performance.now();
    // noir.execute expects an object matching the ABI (e.g., { input_name: value, ... })
    const { witness } = await noir.execute(inputs);
    const witnessGenEnd = performance.now();
    const witnessGenTime = witnessGenEnd - witnessGenStart;
    showAppend("logs", `Generated witness... ✅ (${witnessGenTime.toFixed(2)} ms)`);

    showAppend("logs", "Generating proof... ⏳");
    const proofGenStart = performance.now();
    const proofData = await backend.generateProof(witness);
    const proofGenEnd = performance.now();
    const proofGenTime = proofGenEnd - proofGenStart;
    showAppend("logs", `Generated proof... ✅ (${proofGenTime.toFixed(2)} ms)`);
    
    const proofSize = proofData.proof instanceof Uint8Array ? proofData.proof.length : JSON.stringify(proofData.proof).length;

    // Clear previous results and show new ones
    show("results", ""); 
    showAppend("results", `Proof Size: ${proofSize} bytes`);
    showAppend("results", `Witness Generation Time: ${witnessGenTime.toFixed(2)} ms`);
    showAppend("results", `Proof Generation Time: ${proofGenTime.toFixed(2)} ms`);


    showAppend("logs", "Verifying proof... ⏳");
    const verificationStart = performance.now();
    // The backend, now initialized with the correct SRS, will use it for verification.
    // The verification key is derived by the backend from the ACIR.
    const isValid = await backend.verifyProof(proofData);
    const verificationEnd = performance.now();
    const verificationTime = verificationEnd - verificationStart;
    showAppend("logs", `Proof is ${isValid ? "valid" : "invalid"}... ✅ (${verificationTime.toFixed(2)} ms)`);
    showAppend("results", `Proof Verification Time: ${verificationTime.toFixed(2)} ms`);

  } catch (err) {
    console.error(err);
    showAppend("logs", `Oh 💔: ${err.message}`);
    // Add more detailed error to log
    if (err.stack) {
      showAppend("logs", `Stack: ${err.stack}`);
    }
  }
});
