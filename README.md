# TOTP Generator and Verifier (Data Security Final Project)

A Python-based Time-Based One-Time Password (TOTP) generator and verifier with a Tkinter GUI. The project demonstrates how TOTP, as defined in RFC 6238, can be implemented for secure user authentication. It includes a live countdown timer, dynamic TOTP generation, and user code validation.

This project was created as the final project for a Data Security course.

## Features

- TOTP generation using a shared secret key and time synchronization.
- User-friendly Tkinter GUI with:
  - Real-time TOTP code display.
  - Countdown timer indicating the time left for the current TOTP code.
  - User input verification with success and failure notifications.
- Fully documented Python implementation.

## Prerequisites

- Python 3.7 or later installed on your system.
- Basic familiarity with Python and virtual environments (optional but recommended).

## Setup and Installation

Follow these steps to set up and run the project:

### 1. Clone the Repository

First, clone this repository to your local system:

```bash
git clone https://github.com/your-username/totp-project.git
cd totp-project
```

### 2. Create a Virtual Environment

It is recommended to create a virtual environment to isolate project dependencies:

```bash
python -m venv venv
```

Activate the virtual environment:

On Windows:

```bash
venv\Scripts\activate
```

On macOS/Linux:

```bash
source venv/bin/activate
```

### 3. Install Dependencies

Install the required dependencies listed in the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

### 4. Run the Application

Start the TOTP application:

```bash
python totp_implementation.py
```

## Usage

### Launch the GUI:

The GUI will display the current TOTP code and a countdown timer showing how much time is left before the code expires.

### Enter the Code:

Enter the TOTP code displayed in the app into the input box.

### Verify the Code:

Click the "Verify" button to validate the code.

- If successful, the GUI will display a success message and close.
- If the code is invalid or expired, an error message will be shown, and the GUI will remain open.

## Project Files

- `totp_implementation.py`: Main Python script containing the TOTP implementation and Tkinter GUI.
- `requirements.txt`: File listing any dependencies required to run the project.
- `.gitignore`: File specifying which files and folders (like `venv/`) to exclude from version control.

## How TOTP Works

### Secret Key Setup:

The server and the user share a secret key during setup.

### Code Generation:

The TOTP algorithm combines the secret key and the current time (synchronized in 30-second intervals) to generate a unique 6-digit code.

### Verification:

The server calculates the expected TOTP code for the current time and compares it with the user’s input.

TOTP ensures secure and time-sensitive authentication without requiring persistent connections or key exchanges.

## Example GUI

The GUI displays:

- The current TOTP code.
- A live countdown timer.
- An input box for users to enter their TOTP code.
- A button to verify the code.

## Troubleshooting

- **Tkinter not found**: Ensure Tkinter is installed. It is typically included with Python. If not:
  ```bash
  pip install tk
  ```
- **Code mismatch**: Ensure your system clock is synchronized with internet time to avoid discrepancies in TOTP generation.
- **Dependencies not installing**: Double-check that the virtual environment is activated before running `pip install`.

## Contributing

If you’d like to contribute to this project, feel free to fork the repository and submit a pull request. All contributions are welcome!

## Acknowledgments

- RFC 6238: Time-Based One-Time Password Algorithm.
- Python’s standard libraries for making this project straightforward and efficient.
