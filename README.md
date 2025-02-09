# TOTP Authenticator

## Overview
This project is a **Time-based One-Time Password (TOTP) Authenticator** implemented in Python using `tkinter` for GUI. It supports SHA-1, SHA-256, and SHA-512 algorithms, along with a time window tolerance for verification.

The implementation is designed for two-factor authentication (2FA) systems, providing time-based security codes that refresh every 30 seconds.

## Features
- **TOTP Code Generation**: Supports SHA-1, SHA-256, and SHA-512 algorithms.
- **Time Window Tolerance**: Verifies codes with optional flexibility in time steps.
- **RFC 6238 Compliance**: Tested with official test vectors.
- **GUI with Tkinter**: User-friendly interface for generating and verifying TOTP codes.
- **HMAC-based One-Time Password (HOTP) Algorithm**: Securely generates OTPs using cryptographic hashing.

## Installation

### Prerequisites
Ensure you have **Python 3.6+** installed on your system. You can check your Python version with:
```sh
python --version
```

### Clone the Repository
```sh
git clone https://github.com/RonyBubnovsky/TOTP-Data-Security.git
cd TOTP-Data-Security
```

### Install Dependencies
This project uses only Python standard libraries, so no additional dependencies are required.

## Running the Application
To start the TOTP Authenticator, run:
```sh
python totp_implementation.py
```
This will launch a GUI where you can view, generate, and verify TOTP codes.

## How It Works
1. The application generates a 6-digit TOTP code based on a **shared secret key** and **current time**.
2. The user enters the generated code to verify authentication.
3. The system supports **SHA-1, SHA-256, and SHA-512** algorithms.
4. The application updates the TOTP code every 30 seconds.

## TOTP Generation
The function below generates a **6-digit TOTP code** using SHA-1 (default), SHA-256, or SHA-512:
```python
def generate_totp(secret_key, time_step=30, digits=6, current_time=None, algo="SHA1"):
    if current_time is None:
        current_time = int(time.time())
    key = base64.b32decode(secret_key)
    time_counter = current_time // time_step
    time_bytes = struct.pack(">Q", time_counter)

    if algo.upper() == "SHA256":
        hmac_hash = hmac.new(key, time_bytes, hashlib.sha256).digest()
    elif algo.upper() == "SHA512":
        hmac_hash = hmac.new(key, time_bytes, hashlib.sha512).digest()
    else:
        hmac_hash = hmac.new(key, time_bytes, hashlib.sha1).digest()

    offset = hmac_hash[-1] & 0x0F
    truncated_hash = hmac_hash[offset:offset + 4]
    code_int = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)
```

## Verifying a TOTP Code
To verify a user-entered TOTP code, use the function below. It supports **window_size**, allowing time tolerance for slight delays.
```python
def verify_code(user_input, secret_key=SECRET_KEY, window_size=0, time_step=30, algo="SHA1"):
    if not user_input.isdigit():
        return False
    current_time = int(time.time())
    for time_offset in range(-window_size, window_size + 1):
        check_time = current_time + (time_offset * time_step)
        totp = generate_totp(secret_key, time_step, current_time=check_time, algo=algo)
        if hmac.compare_digest(user_input.encode('utf-8'), totp.encode('utf-8')):
            return True
    return False
```

## Running RFC 6238 Test Vectors
The application includes an **RFC 6238 test suite** to verify its correctness using standardized test cases.
To run these tests:
1. Start the GUI
2. Click **"Test RFC Vectors"**
3. The results will display in a message box, showing pass/fail for each test case.

## Contributing
Contributions are welcome! 🎉 If you have ideas, bug fixes, or improvements, feel free to **fork** this repository and submit a **pull request**. Please ensure that your contributions align with the project's goals and follow best practices.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.






