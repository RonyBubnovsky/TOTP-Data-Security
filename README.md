# TOTP Generator and Verifier

A Python-based Time-Based One-Time Password (TOTP) generator and verifier with a Tkinter GUI. The project demonstrates how TOTP, as defined in RFC 6238, can be implemented for secure user authentication. It includes a live countdown timer, dynamic TOTP generation, detailed generation steps visualization, and built-in RFC test vectors.

## Features

- TOTP generation using a shared secret key and time synchronization
- User-friendly Tkinter GUI with:
  - Real-time TOTP code display
  - Countdown timer indicating time remaining for current code
  - User input verification with success/failure notifications
  - Detailed step-by-step TOTP generation visualization
  - Built-in RFC 6238 test vector verification
- Two-tab interface:
  - Main tab for code generation and verification
  - Details tab showing all intermediate TOTP calculation steps
- Support for RFC 6238 compliance testing
- Constant-time comparison for secure code verification

## Prerequisites

- Python 3.7 or later

## Installation

1. Clone the repository:
```bash
git clone https://github.com/RonyBubnovsky/TOTP-Data-Security
cd totp-implementation
```

2. Create and activate a virtual environment (optional but recommended):
```bash
# Create virtual environment
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on macOS/Linux
source venv/bin/activate
```

3. No additional dependencies required - all libraries used are part of Python's standard library

## Usage

Run the application:
```bash
python totp_implementation.py
```

### Main Tab
- Displays current TOTP code in large font
- Shows countdown timer for code expiration
- Provides input field for code verification
- Includes RFC test vector verification button

### Details Tab
Displays real-time information about the TOTP generation process:
- Secret Key (Base32 encoded)
- Decoded Secret (in hexadecimal)
- Time Counter value
- Time Bytes (in hexadecimal)
- HMAC-SHA1 Hash
- Dynamic Truncation Offset
- Truncated Hash value
- Intermediate Code value
- Final TOTP Code

### Verification
1. Enter the displayed TOTP code in the input field
2. Click "Verify" button
3. System will show success/failure message
4. On success, application closes automatically

### RFC Test Vectors
Click "Test RFC Vectors" to run compliance tests against standard RFC 6238 test vectors.

## Technical Implementation

### TOTP Generation Process
1. Base32 decode the secret key
2. Calculate time counter (current time ÷ 30 seconds)
3. Generate HMAC-SHA1 hash
4. Perform dynamic truncation
5. Convert to 6-digit code

### Security Features
- Constant-time comparison for code verification
- Time window tolerance for verification
- Secure handling of secret keys
- RFC 6238 compliance

## Code Structure

Main components:
- `generate_totp()`: Core TOTP generation with detailed step tracking
- `verify_code()`: Secure code verification with time window support
- `update_interface()`: GUI update mechanism
- `test_with_rfc_vectors()`: RFC compliance testing
- Tkinter GUI implementation with tabbed interface

## Troubleshooting

Common issues and solutions:
- **Tkinter not found**: Ensure Python was installed with Tkinter support
- **Clock synchronization**: System time must be accurate for correct TOTP generation
- **Window doesn't close after verification**: Check if code matches within time window


## Acknowledgments

- RFC 6238 specification
- Python standard library
