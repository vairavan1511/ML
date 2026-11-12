# ThreatShield: five-minute demo

The timings below add up to five minutes. Start with the app running and use the current on-screen output; model scores and verdicts can change with the model artifacts.

## Demo flow

### 1. Email sample — 0:00–0:45

- **Action:** Open the Email tab, select **Try a sample (synthetic phishing email)**, then click **Analyze**.
- **Point at:** The red **SPAM-PHISHING** badge, reasons list, and suspicious words highlighted in the preview.
- **Say:** “The sample is flagged as SPAM-PHISHING, and the reasons and highlighted words show which message features contributed to that result.”

### 2. Link Shield — 0:45–1:20

- **Action:** Click a locked link chip in the result.
- **Point at:** The Link Shield modal and its defanged link; do not use **Open in new tab**.
- **Say:** “Links are never opened automatically; a single click only shows this safety modal.”

### 3. Download report — 1:20–1:50

- **Action:** Close the modal if needed, then click **Download report**.
- **Point at:** The case ID, reasons, defanged links, and SHA-256 footer in the PDF.
- **Say:** “The PDF records the case ID, reasons, and defanged links, with a SHA-256 hash of the report text for integrity checking.”

### 4. SMS OTP sample — 1:50–2:30

- **Action:** Open the SMS tab, select **Try a sample (synthetic OTP scam)**, then click **Analyze**.
- **Point at:** The verdict and reasons that identify the OTP request.
- **Say:** “The result combines SMS pattern checks with the ML model; here it detects the request to share an OTP.”

### 5. UPI collect-request sample — 2:30–3:10

- **Action:** In the SMS tab, paste the contents of [`threatshield/samples/upi_collect_sms.txt`](../threatshield/samples/upi_collect_sms.txt) and click **Analyze**.
- **Point at:** The UPI collect/payment reason and the resulting verdict.
- **Say:** “This synthetic example illustrates an India-specific UPI collect-request lure detected by the SMS pattern checks and the model.”

### 6. Benign SMS sample — 3:10–3:50

- **Action:** In the SMS tab, paste the contents of [`threatshield/samples/safe_sms.txt`](../threatshield/samples/safe_sms.txt) and click **Analyze**.
- **Point at:** The **SAFE** verdict and the advice card.
- **Say:** “This friendly personal message currently receives a SAFE verdict, and the advice card switches to the safe-message guidance.”

### 7. Model and Accuracy — 3:50–5:00

- **Action:** Scroll to **Model and Accuracy**.
- **Point at:** The best model and the displayed test metrics.
- **Say:** “These values come from `ml/artifacts/metrics.json`, which the app reads at runtime; I’ll refer to the displayed values rather than quote fixed numbers.”

## Likely examiner questions

**How representative are the datasets?**  
The public datasets are older and mostly English. Results may not generalize to current scams, other languages, or every real-world message.

**Why use synthetic India-specific SMS examples for training only, not testing?**  
They help add India-specific patterns such as UPI lures to training. Keeping synthetic examples out of validation and test data avoids reporting evaluation results on generated examples; it does not prove performance on real-world Indian scams.

**Why LinearSVM instead of DistilBERT?**  
The current artifact identifies LinearSVM as the selected model. The saved comparison covers the models listed in `ml/artifacts/metrics.json`; it does not include DistilBERT, so we cannot claim a measured head-to-head advantage over it. A DistilBERT comparison would require its own training and evaluation.

**Why are geolocation and full header forensics not built yet?**  
The app does not implement geolocation or full header-chain forensics. Email analysis has limited header signals, but not a complete forensic investigation; a reliable location or attribution claim would need additional trusted data and careful validation.

**Is the report legally admissible?**  
No such claim is made. The SHA-256 value is an integrity hash, not a digital signature: it does not identify a signer or establish chain of custody. Legal admissibility depends on the evidence and applicable rules.

**How does the model handle VPN or Tor?**  
It does not geolocate senders. There is no geolocation feature, so the app cannot determine a sender’s actual location behind a VPN, Tor, or another relay.

**What does the risk score mean?**  
It is a 0–100 composite risk indicator based on the ML score and channel-specific signals, such as URL and SMS-pattern checks or email header and attachment checks. It is not a probability that the message is malicious and is not a guarantee of safety.
