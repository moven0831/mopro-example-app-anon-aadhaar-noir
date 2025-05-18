package com.example.moproapp

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONObject
import uniffi.mopro.proveAnonAadhaarSimple
import uniffi.mopro.verifyAnonAadhaarSimple
import java.io.File
import java.io.InputStream

@Composable
fun AnonAadhaarComponent() {
    val context = LocalContext.current
    var provingTime by remember { mutableStateOf("") }
    var proofResult by remember { mutableStateOf("") }
    var verificationTime by remember { mutableStateOf("") }
    var verificationResult by remember { mutableStateOf("") }
    var proofBytes by remember { mutableStateOf<ByteArray?>(null) }

    // Status states
    var isGeneratingProof by remember { mutableStateOf(false) }
    var isVerifyingProof by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("Ready to generate proof") }

    val srsFileName = "anon_srs.local"
    val inputsJsonFileName = "anon_aadhaar_inputs.json"

    // Function to prepare AnonAadhaar inputs from JSON file in assets
    fun prepareAnonAadhaarInputs(): List<String> {
        val inputsList = mutableListOf<String>()
        try {
            context.assets.open(inputsJsonFileName).bufferedReader().use { reader ->
                val jsonString = reader.readText()
                val jsonObject = JSONObject(jsonString)

                // Extract data in the specific order required by proveAnonAadhaarSimple
                val qrDataPadded = jsonObject.getJSONObject("qrDataPadded")
                val qrDataPaddedStorage = qrDataPadded.getJSONArray("storage")
                for (i in 0 until qrDataPaddedStorage.length()) {
                    inputsList.add(qrDataPaddedStorage.getString(i))
                }
                inputsList.add(qrDataPadded.getString("len"))

                inputsList.add(jsonObject.getString("qrDataPaddedLength"))

                val delimiterIndices = jsonObject.getJSONArray("delimiterIndices")
                for (i in 0 until delimiterIndices.length()) {
                    inputsList.add(delimiterIndices.getString(i))
                }

                val signatureLimbs = jsonObject.getJSONArray("signature_limbs")
                for (i in 0 until signatureLimbs.length()) {
                    inputsList.add(signatureLimbs.getString(i))
                }

                val modulusLimbs = jsonObject.getJSONArray("modulus_limbs")
                for (i in 0 until modulusLimbs.length()) {
                    inputsList.add(modulusLimbs.getString(i))
                }

                val redcLimbs = jsonObject.getJSONArray("redc_limbs")
                for (i in 0 until redcLimbs.length()) {
                    inputsList.add(redcLimbs.getString(i))
                }

                inputsList.add(jsonObject.getString("revealAgeAbove18"))
                inputsList.add(jsonObject.getString("revealGender"))
                inputsList.add(jsonObject.getString("revealPinCode"))
                inputsList.add(jsonObject.getString("revealState"))
                inputsList.add(jsonObject.getString("nullifierSeed"))
                inputsList.add(jsonObject.getString("signalHash"))
            }
        } catch (e: Exception) {
            e.printStackTrace()
            // Update status message or handle error appropriately
            statusMessage = "Error loading inputs: ${e.message}"
            // Return empty or throw, depending on desired error handling
        }
        return inputsList
    }

    // Function to ensure SRS file is available
    fun prepareSrsFile(): String {
        val srsFile = File(context.filesDir, srsFileName)
        if (!srsFile.exists()) {
            try {
                context.assets.open(srsFileName).use { input ->
                    srsFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                statusMessage = "Error preparing SRS file: ${e.message}"
            }
        }
        return srsFile.absolutePath
    }

    Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "Anon Aadhaar (Noir)",
                modifier = Modifier.padding(bottom = 20.dp),
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp
            )

            // Status message with prominent styling
            Text(
                text = statusMessage,
                modifier = Modifier.padding(bottom = 24.dp),
                textAlign = TextAlign.Center,
                fontSize = 16.sp,
                fontWeight = if (isGeneratingProof || isVerifyingProof) FontWeight.Bold else FontWeight.Normal
            )

            // Progress indicator when operations are running
            if (isGeneratingProof || isVerifyingProof) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(bottom = 16.dp)
                )
            }

            Button(
                onClick = {
                    isGeneratingProof = true
                    provingTime = ""
                    proofResult = ""
                    statusMessage = "Generating Anon Aadhaar proof... This may take some time"

                    Thread(
                        Runnable {
                            try {
                                val srsPath = prepareSrsFile()
                                val inputs = prepareAnonAadhaarInputs()
                                
                                if (inputs.isEmpty() && statusMessage.startsWith("Error loading inputs")) {
                                    // Inputs failed to load, error message already set by prepareAnonAadhaarInputs
                                    isGeneratingProof = false
                                    return@Runnable
                                }
                                if (srsPath.isEmpty() && statusMessage.startsWith("Error preparing SRS file")){
                                    isGeneratingProof = false
                                    return@Runnable
                                }

                                val startTime = System.currentTimeMillis()
                                proofBytes = proveAnonAadhaarSimple(srsPath, inputs)
                                val endTime = System.currentTimeMillis()
                                val duration = endTime - startTime

                                provingTime = "Proving time: $duration ms"
                                proofResult = "Anon Aadhaar proof generated: ${proofBytes?.size ?: 0} bytes"
                                statusMessage = "Anon Aadhaar proof generation completed"
                            } catch (e: Exception) {
                                provingTime = "Proving failed"
                                proofResult = "Error: ${e.message}"
                                statusMessage = "Anon Aadhaar proof generation failed"
                                e.printStackTrace()
                            } finally {
                                isGeneratingProof = false
                            }
                        }
                    ).start()
                },
                modifier = Modifier.padding(top = 20.dp).testTag("anonAadhaarGenerateProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof
            ) { 
                Text(text = "Generate Anon Aadhaar Proof")
            }

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = {
                    isVerifyingProof = true
                    verificationTime = ""
                    verificationResult = ""
                    statusMessage = "Verifying Anon Aadhaar proof..."

                    Thread(
                        Runnable {
                            try {
                                proofBytes?.let { proof ->
                                    val srsPath = prepareSrsFile()
                                    if (srsPath.isEmpty() && statusMessage.startsWith("Error preparing SRS file")){
                                        isVerifyingProof = false
                                        return@Runnable
                                    }

                                    val startTime = System.currentTimeMillis()
                                    val result = verifyAnonAadhaarSimple(srsPath, proof)
                                    val endTime = System.currentTimeMillis()
                                    val duration = endTime - startTime

                                    verificationTime = "Verification time: $duration ms"
                                    verificationResult = "Verification result: $result"
                                    if (result)
                                        statusMessage = "Anon Aadhaar proof verified successfully!" 
                                    else 
                                        statusMessage = "Anon Aadhaar proof verification failed!"
                                } ?: run {
                                    verificationResult = "No proof available"
                                    statusMessage = "Please generate an Anon Aadhaar proof first"
                                }
                            } catch (e: Exception) {
                                verificationTime = "Verification failed"
                                verificationResult = "Error: ${e.message}"
                                statusMessage = "Anon Aadhaar proof verification error"
                                e.printStackTrace()
                            } finally {
                                isVerifyingProof = false
                            }
                        }
                    ).start()
                },
                modifier = Modifier.padding(top = 20.dp).testTag("anonAadhaarVerifyProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof && proofBytes != null
            ) { 
                Text(text = "Verify Anon Aadhaar Proof")
            }

            Spacer(modifier = Modifier.height(40.dp))

            // Results displayed in a more organized way
            if (provingTime.isNotEmpty() || proofResult.isNotEmpty() || 
                verificationTime.isNotEmpty() || verificationResult.isNotEmpty()) {

                Text(
                    text = "Results",
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                    modifier = Modifier.padding(bottom = 8.dp)
                )

                if (provingTime.isNotEmpty()) {
                    Text(
                        text = provingTime,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (proofResult.isNotEmpty()) {
                    Text(
                        text = proofResult,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (verificationTime.isNotEmpty()) {
                    Text(
                        text = verificationTime,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (verificationResult.isNotEmpty()) {
                    Text(
                        text = verificationResult,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center,
                        fontWeight = if (verificationResult.contains("true")) FontWeight.Bold else FontWeight.Normal
                    )
                }
            }
        }
    }
} 