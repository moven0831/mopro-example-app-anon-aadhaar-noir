//
//  ContentView.swift
//  MoproApp
//
import SwiftUI
import moproFFI

// Structs for parsing anon_aadhaar_inputs.json
struct AnonAadhaarQrDataPadded: Decodable {
    let storage: [String]
    let len: String
}

struct AnonAadhaarInputs: Decodable {
    let qrDataPadded: AnonAadhaarQrDataPadded
    let qrDataPaddedLength: String
    let delimiterIndices: [String]
    let signature_limbs: [String]
    let modulus_limbs: [String]
    let redc_limbs: [String]
    let revealAgeAbove18: String
    let revealGender: String
    let revealPinCode: String
    let revealState: String
    let nullifierSeed: String
    let signalHash: String
}

func serializeOutputs(_ stringArray: [String]) -> [UInt8] {
    var bytesArray: [UInt8] = []
    let length = stringArray.count
    var littleEndianLength = length.littleEndian
    let targetLength = 32
    withUnsafeBytes(of: &littleEndianLength) {
        bytesArray.append(contentsOf: $0)
    }
    for value in stringArray {
        // TODO: should handle 254-bit input
        var littleEndian = Int32(value)!.littleEndian
        var byteLength = 0
        withUnsafeBytes(of: &littleEndian) {
            bytesArray.append(contentsOf: $0)
            byteLength = byteLength + $0.count
        }
        if byteLength < targetLength {
            let paddingCount = targetLength - byteLength
            let paddingArray = [UInt8](repeating: 0, count: paddingCount)
            bytesArray.append(contentsOf: paddingArray)
        }
    }
    return bytesArray
}

struct ContentView: View {
    @State private var textViewText = ""
    @State private var isCircomProveButtonEnabled = true
    @State private var isCircomVerifyButtonEnabled = false
    @State private var isHalo2roveButtonEnabled = true
    @State private var isHalo2VerifyButtonEnabled = false
    @State private var generatedCircomProof: CircomProof?
    @State private var circomPublicInputs: [String]?
    @State private var generatedHalo2Proof: Data?
    @State private var halo2PublicInputs: Data?
    @State private var isAnonAadhaarProveButtonEnabled = true
    @State private var isAnonAadhaarVerifyButtonEnabled = false
    @State private var generatedAnonAadhaarProof: Data?
    private let zkeyPath = Bundle.main.path(forResource: "multiplier2_final", ofType: "zkey")!
    private let srsPath = Bundle.main.path(forResource: "plonk_fibonacci_srs.bin", ofType: "")!
    private let vkPath = Bundle.main.path(forResource: "plonk_fibonacci_vk.bin", ofType: "")!
    private let pkPath = Bundle.main.path(forResource: "plonk_fibonacci_pk.bin", ofType: "")!
    
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Button("Prove Circom", action: runCircomProveAction).disabled(!isCircomProveButtonEnabled).accessibilityIdentifier("proveCircom")
            Button("Verify Circom", action: runCircomVerifyAction).disabled(!isCircomVerifyButtonEnabled).accessibilityIdentifier("verifyCircom")
            Button("Prove Halo2", action: runHalo2ProveAction).disabled(!isHalo2roveButtonEnabled).accessibilityIdentifier("proveHalo2")
            Button("Verify Halo2", action: runHalo2VerifyAction).disabled(!isHalo2VerifyButtonEnabled).accessibilityIdentifier("verifyHalo2")
            Button("Prove Anon Aadhaar", action: runAnonAadhaarProveAction).disabled(!isAnonAadhaarProveButtonEnabled).accessibilityIdentifier("proveAnonAadhaar")
            Button("Verify Anon Aadhaar", action: runAnonAadhaarVerifyAction).disabled(!isAnonAadhaarVerifyButtonEnabled).accessibilityIdentifier("verifyAnonAadhaar")

            ScrollView {
                Text(textViewText)
                    .padding()
                    .accessibilityIdentifier("proof_log")
            }
            .frame(height: 200)
        }
        .padding()
    }
}

extension ContentView {
    func runCircomProveAction() {
        textViewText += "Generating Circom proof... "
        do {
            // Prepare inputs
            let a = 3
            let b = 5
            let c = a*b
            let input_str: String = "{\"b\":[\"5\"],\"a\":[\"3\"]}"

            // Expected outputs
            let outputs: [String] = [String(c), String(a)]

            let start = CFAbsoluteTimeGetCurrent()

            // Generate Proof
            let generateProofResult = try generateCircomProof(zkeyPath: zkeyPath, circuitInputs: input_str, proofLib: ProofLib.arkworks)
            assert(!generateProofResult.proof.a.x.isEmpty, "Proof should not be empty")
            assert(outputs == generateProofResult.inputs, "Circuit outputs mismatch the expected outputs")

            let end = CFAbsoluteTimeGetCurrent()
            let timeTaken = end - start

            // Store the generated proof and public inputs for later verification
            generatedCircomProof = generateProofResult.proof
            circomPublicInputs = generateProofResult.inputs

            textViewText += "\(String(format: "%.3f", timeTaken))s 1️⃣\n"

            isCircomVerifyButtonEnabled = true
        } catch {
            textViewText += "\nProof generation failed: \(error.localizedDescription)\n"
        }
    }
    
    func runCircomVerifyAction() {
        guard let proof = generatedCircomProof,
              let inputs = circomPublicInputs else {
            textViewText += "Proof has not been generated yet.\n"
            return
        }
        
        textViewText += "Verifying Circom proof... "
        do {
            let start = CFAbsoluteTimeGetCurrent()
            
            let isValid = try verifyCircomProof(zkeyPath: zkeyPath, proofResult: CircomProofResult(proof: proof, inputs: inputs), proofLib: ProofLib.arkworks)
            let end = CFAbsoluteTimeGetCurrent()
            let timeTaken = end - start
            
            assert(proof.a.x.count > 0, "Proof should not be empty")
            assert(inputs.count > 0, "Inputs should not be empty")
            
            print("Ethereum Proof: \(proof)\n")
            print("Ethereum Inputs: \(inputs)\n")
            
            if isValid {
                textViewText += "\(String(format: "%.3f", timeTaken))s 2️⃣\n"
            } else {
                textViewText += "\nProof verification failed.\n"
            }
            isCircomVerifyButtonEnabled = false
        } catch let error as MoproError {
            print("\nMoproError: \(error)")
        } catch {
            print("\nUnexpected error: \(error)")
        }
    }
    
    func runHalo2ProveAction() {
        textViewText += "Generating Halo2 proof... "
        do {
            // Prepare inputs
            var inputs = [String: [String]]()
            let out = 55
            inputs["out"] = [String(out)]
            
            let start = CFAbsoluteTimeGetCurrent()
            
            // Generate Proof
            let generateProofResult = try generateHalo2Proof(srsPath: srsPath, pkPath: pkPath, circuitInputs: inputs)
            assert(!generateProofResult.proof.isEmpty, "Proof should not be empty")
            assert(!generateProofResult.inputs.isEmpty, "Inputs should not be empty")

            
            let end = CFAbsoluteTimeGetCurrent()
            let timeTaken = end - start
            
            // Store the generated proof and public inputs for later verification
            generatedHalo2Proof = generateProofResult.proof
            halo2PublicInputs = generateProofResult.inputs
            
            textViewText += "\(String(format: "%.3f", timeTaken))s 1️⃣\n"
            
            isHalo2VerifyButtonEnabled = true
        } catch {
            textViewText += "\nProof generation failed: \(error.localizedDescription)\n"
        }
    }
    
    func runHalo2VerifyAction() {
        guard let proof = generatedHalo2Proof,
              let inputs = halo2PublicInputs else {
            textViewText += "Proof has not been generated yet.\n"
            return
        }
        
        textViewText += "Verifying Halo2 proof... "
        do {
            let start = CFAbsoluteTimeGetCurrent()
            
            let isValid = try verifyHalo2Proof(
              srsPath: srsPath, vkPath: vkPath, proof: proof, publicInput: inputs)
            let end = CFAbsoluteTimeGetCurrent()
            let timeTaken = end - start

            
            if isValid {
                textViewText += "\(String(format: "%.3f", timeTaken))s 2️⃣\n"
            } else {
                textViewText += "\nProof verification failed.\n"
            }
            isHalo2VerifyButtonEnabled = false
        } catch let error as MoproError {
            print("\nMoproError: \(error)")
        } catch {
            print("\nUnexpected error: \(error)")
        }
    }

    func runAnonAadhaarProveAction() {
        textViewText += "Generating Anon Aadhaar proof... "

        // Use "anon_srs.local"
        guard let srsPath = Bundle.main.path(forResource: "anon_srs", ofType: "local") else {
            DispatchQueue.main.async {
                self.textViewText += "\nError: Could not find anon_srs.local in app bundle.\n"
            }
            return
        }
        
        // Load inputs from JSON
        guard let parsedInputs = loadAnonAadhaarInputsFromFile() else {
            // Error message is handled by loadAnonAadhaarInputsFromFile
            return
        }
        
        // Construct the flat input array in the correct order
        var inputs: [String] = []
        inputs.append(contentsOf: parsedInputs.qrDataPadded.storage)
        inputs.append(parsedInputs.qrDataPadded.len)
        inputs.append(parsedInputs.qrDataPaddedLength)
        inputs.append(contentsOf: parsedInputs.delimiterIndices)
        inputs.append(contentsOf: parsedInputs.signature_limbs)
        inputs.append(contentsOf: parsedInputs.modulus_limbs)
        inputs.append(contentsOf: parsedInputs.redc_limbs)
        inputs.append(parsedInputs.revealAgeAbove18)
        inputs.append(parsedInputs.revealGender)
        inputs.append(parsedInputs.revealPinCode)
        inputs.append(parsedInputs.revealState)
        inputs.append(parsedInputs.nullifierSeed)
        inputs.append(parsedInputs.signalHash)

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let start = CFAbsoluteTimeGetCurrent()

                // Call the FFI function proveAnonAadhaarSimple
                let proofData = try proveAnonAadhaarSimple(srsPath: srsPath, inputs: inputs)
                assert(!proofData.isEmpty, "Proof should not be empty")

                let end = CFAbsoluteTimeGetCurrent()
                let timeTaken = end - start

                DispatchQueue.main.async {
                    self.generatedAnonAadhaarProof = proofData
                    self.textViewText += "\(String(format: "%.3f", timeTaken))s 1️⃣\n"
                    self.isAnonAadhaarVerifyButtonEnabled = true
                    self.isAnonAadhaarProveButtonEnabled = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.textViewText += "\nAnon Aadhaar proof generation failed: \(error.localizedDescription)\n"
                }
            }
        }
    }

    func runAnonAadhaarVerifyAction() {
        guard let proofData = generatedAnonAadhaarProof else {
            textViewText += "Anon Aadhaar proof has not been generated yet.\n"
            return
        }

        // Use "anon_srs.local"
        guard let srsPath = Bundle.main.path(forResource: "anon_srs", ofType: "local") else {
            DispatchQueue.main.async {
                self.textViewText += "\nError: Could not find anon_srs.local in app bundle.\n"
            }
            return
        }

        textViewText += "Verifying Anon Aadhaar proof... "

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let start = CFAbsoluteTimeGetCurrent()

                // Call the FFI function verifyAnonAadhaarSimple
                let isValid = try verifyAnonAadhaarSimple(srsPath: srsPath, proof: proofData)
                let end = CFAbsoluteTimeGetCurrent()
                let timeTaken = end - start

                DispatchQueue.main.async {
                    if isValid {
                        self.textViewText += "\(String(format: "%.3f", timeTaken))s 2️⃣\n"
                    } else {
                        self.textViewText += "\nAnon Aadhaar proof verification failed.\n"
                    }
                    self.isAnonAadhaarVerifyButtonEnabled = false
                    self.isAnonAadhaarProveButtonEnabled = true
                }
            } catch let error as MoproError {
                DispatchQueue.main.async {
                    self.textViewText += "\nMoproError: \(error)\n"
                    self.isAnonAadhaarVerifyButtonEnabled = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.textViewText += "\nUnexpected error: \(error.localizedDescription)\n"
                    self.isAnonAadhaarVerifyButtonEnabled = false
                }
            }
        }
    }
}

// Helper function to load and parse inputs from anon_aadhaar_inputs.json
func loadAnonAadhaarInputsFromFile() -> AnonAadhaarInputs? {
    guard let url = Bundle.main.url(forResource: "anon_aadhaar_inputs", withExtension: "json") else {
        // Update UI on the main thread for error reporting
        DispatchQueue.main.async {
            // It's better to update a @State variable that ContentView observes
            // For now, printing to console and updating a static text view if available or a shared error state.
            // This part needs to be adapted to how ContentView manages its state for textViewText.
            // For simplicity, directly trying to update if self is accessible or just printing.
            // A more robust solution would involve passing the view model or a callback.
            print("Error: Could not find anon_aadhaar_inputs.json in app bundle.")
            // If you have access to textViewText or similar state variable here:
            // self.textViewText += "\nError: Could not find anon_aadhaar_inputs.json in app bundle.\n"
        }
        return nil
    }
    do {
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        let inputs = try decoder.decode(AnonAadhaarInputs.self, from: data)
        return inputs
    } catch {
        DispatchQueue.main.async {
            print("Error: Could not parse anon_aadhaar_inputs.json: \(error.localizedDescription)")
            // self.textViewText += "\nError: Could not parse anon_aadhaar_inputs.json: \(error.localizedDescription)\n"
        }
        return nil
    }
}

