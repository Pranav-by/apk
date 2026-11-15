**Static features**  
\- Permissions  
\- Intents  
\- API Calls  
\- Activities  
\- Services  
\- Broadcast Receivers  
\- Content Providers  
\- Intent Filters  
\- AndroidManifest Features  
\- Package Information  
\- Application Components  
\- Sensitive API Calls  
\- Network Features  
\- URLs and Domains  
\- IP Addresses  
\- SMS Features  
\- Telephony Features  
\- File-System Features  
\- Cryptographic Features  
\- Reflection Features  
\- Dynamic Code Loading Indicators  
\- Obfuscation Features  
\- Native API Calls  
\- System Command Indicators  
\- Hardware Features  
\- SDK Versions  
\- Application Metadata  
\- Certificate and Signature Information  
\- DEX Features  
\- Strings and Constants

## **Extract the static features**

| Feature category | Information collected |
| ----- | ----- |
| APK identity | Filename, SHA-256 hash, package name |
| Permissions | Requested Android permissions |
| Intents | Actions and categories declared in intent filters |
| Components | Activities, services, receivers, providers |
| SDK information | Minimum and target SDK versions |
| DEX information | Number of DEX files, defined methods, and classes |
| API indicators | Referenced API methods and selected security-relevant API indicators |
| App metadata | Version information and signing-certificate information where available |

## **Steps**

1. **APK Dataset:** Organize downloaded AndroZoo APKs into benign and malicious folders.  
2. **APK Identification:** Calculate SHA-256 hashes and identify duplicate APKs.  
3. **Static Feature Extraction:** Extract permissions, intents, API calls, activities, services, receivers, providers, SDK versions, and app metadata using Python and Androguard.  
4. **Feature Storage:** Save the extracted features in CSV and JSON formats.  
5. **Feature Preprocessing:** Validate the features, handle missing information, and standardize formats.  
6. **Structured Text Generation:** Convert each APK's static features into readable text for the LLM.  
7. **LLM Classification:** Provide the structured text to an LLM and obtain a benign or malicious prediction.  
8. **Prediction Storage:** Save SHA-256, ground-truth label, predicted label, and explanation in a CSV file.  
9. **Evaluation:** Calculate accuracy, precision, recall, F1-score, and confusion matrix.

## **What static features do we extract?**

| Feature structure | What to collect | Example |
| ----- | ----- | ----- |
| APK identity | Filename, SHA-256, package name | `com.example.app` |
| Permissions | Requested permissions | `INTERNET`, `CAMERA` |
| Intents | Actions and categories | `BOOT_COMPLETED` |
| Activities | Activity names and count | `MainActivity` |
| Services | Service names and count | `MyService` |
| Receivers | Receiver names and count | `BootReceiver` |
| Providers | Content provider names and count | `MyProvider` |
| API references | Referenced methods and API indicators | SMS or network-related methods |
| Classes | Number of defined classes | `150` |
| Methods | Number of defined methods | `820` |
| SDK information | Minimum and target SDK | `minSdk=23`, `targetSdk=35` |
| App metadata | Version name and version code | `1.0`, `10` |
| Signing information | Certificate details, if available | Certificate fingerprint |

