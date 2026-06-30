# UAS Kriptografi - Public Key Infrastructure Simulation

Educational Role-Play Tool for Certificate Authority, Registration Authority, and Custodians

## Overview

This simulation demonstrates core Public Key Infrastructure (PKI) concepts through an interactive, role-based scenario. It uses real cryptographic primitives (RSA-2048, X.509 v3 certificates, RSA-OAEP encryption, and RSASSA-PSS signatures) to provide an authentic learning experience.

The tool is designed for academic use in cryptography courses, allowing students and instructors to explore the complete lifecycle of digital certificates and their application in secure communication.

## Key Features

- **Real Cryptography**: All operations use the `cryptography` library (RSA-2048, SHA-256, OAEP, PSS).
- **X.509 Certificates**: Proper self-signed root CA certificate and CA-issued user certificates.
- **Interactive Menu**: Choose individual steps or run the complete scenario.
- **Professional Output**: Clean terminal interface suitable for classroom demonstration and documentation.
- **Role-Play Coverage**:
  - Certificate Authority (CA)
  - Registration Authority (RA)
  - Multiple Custodians (users)
  - Confidential messaging with encryption + digital signature
  - Public announcements with signature verification
  - Tamper/integrity detection

## How to Run

```bash
# Clone the repository
git clone https://github.com/OnlyOneArthur/UAS-kriptografi-sms-4.git
cd UAS-kriptografi-sms-4
git checkout pki-roleplay-simulation

# Install dependency
pip install -r requirements.txt

# Run the simulation
python pki_uas_simulation.py
```

The program presents a numbered menu. Select options 1–9 to explore different aspects of the PKI workflow.

## Menu Options

1. Initialize PKI Infrastructure (Certificate Authority + Registration Authority)  
2. Register Users and Issue X.509 Certificates  
3. Display Public Key Repository and Certificate Status  
4. Custodian-01: Send Confidential Message with Digital Signature  
5. Custodian-02: Issue Signed Public Announcement  
6. Custodian-02: Decrypt and Verify Received Confidential Message  
7. Third-Party Verification of Public Announcement  
8. Demonstrate Message Integrity Protection (Tamper Detection)  
9. Execute Complete Role-Play Scenario (All Steps)  
0. Exit

## Cryptographic Details

- **Key Generation**: 2048-bit RSA
- **Certificate Standard**: X.509 v3
- **Signature Algorithm**: RSASSA-PSS with SHA-256
- **Encryption Algorithm**: RSA-OAEP with SHA-256
- **Hash Function**: SHA-256

All operations are performed using industry-standard libraries and follow current best practices for educational demonstration.

## Educational Value

This simulator illustrates the following PKI concepts in a practical, observable way:

- Separation of duties between CA and RA
- Certificate issuance and trusted repository
- Digital signatures for authentication and integrity
- Asymmetric encryption for confidentiality
- Trust model based on CA-issued certificates
- Detection of message tampering

## Recommended Use in Presentations

- Run the program live during the presentation.
- Use individual menu options to focus on specific concepts.
- Capture screenshots of certificate details, encryption steps, and verification results.
- Emphasize that all cryptographic operations are real (not simulated).

## File Structure

- `pki_uas_simulation.py` — Main interactive simulation (no inline comments)
- `README.md` — This documentation
- `requirements.txt` — Python dependencies

## License & Attribution

Created for the UAS Kriptografi course as an educational tool. Feel free to adapt for similar academic purposes.

For questions or improvements, contact the course group.
