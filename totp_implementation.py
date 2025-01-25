import hmac
import hashlib
import time
import base64
import struct
import tkinter as tk
from tkinter import messagebox

# Shared Secret Key (Base32-encoded for easier handling)
SECRET_KEY = "JBSWY3DPEHPK3PXP"  # Example shared secret key (Google Authenticator-compatible)

def generate_totp(secret_key, time_step=30, digits=6):
    """
    Generate a TOTP code based on the shared secret and current time.
    """
    # Decode the Base32 secret key
    key = base64.b32decode(secret_key)

    # Calculate the current time step
    current_time = int(time.time())
    time_counter = current_time // time_step

    # Pack the time counter into an 8-byte array (big-endian)
    time_bytes = struct.pack(">Q", time_counter)

    # Generate HMAC-SHA1 from the key and time counter
    hmac_hash = hmac.new(key, time_bytes, hashlib.sha1).digest()

    # Dynamic truncation: Extract a 4-byte slice from the hash
    offset = hmac_hash[-1] & 0x0F
    truncated_hash = hmac_hash[offset:offset + 4]

    # Convert the truncated hash to an integer
    code = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF

    # Modulo to get the final TOTP value (e.g., 6 digits)
    totp_code = code % (10 ** digits)

    # Return the TOTP code as a zero-padded string
    return str(totp_code).zfill(digits)


def verify_totp(input_code, secret_key, time_step=30, digits=6, allowed_drift=1):
    """
    Verify the user-provided TOTP code against the server-generated code.
    """
    current_time = int(time.time())
    for drift in range(-allowed_drift, allowed_drift + 1):
        time_counter = (current_time // time_step) + drift
        time_bytes = struct.pack(">Q", time_counter)
        key = base64.b32decode(secret_key)
        hmac_hash = hmac.new(key, time_bytes, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        truncated_hash = hmac_hash[offset:offset + 4]
        code = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
        totp_code = str(code % (10 ** digits)).zfill(digits)
        if totp_code == input_code:
            return True
    return False


# GUI Functionality
def update_totp():
    """
    Update the TOTP display and countdown timer in the GUI.
    """
    global totp_label, timer_label

    # Generate the current TOTP code
    totp_code = generate_totp(SECRET_KEY)
    totp_label.config(text=f"TOTP Code: {totp_code}")

    # Calculate remaining time in the current time step
    time_remaining = 30 - (int(time.time()) % 30)
    timer_label.config(text=f"Time Remaining: {time_remaining}s")

    # Schedule the next update (every 200ms)
    root.after(200, update_totp)


def submit_code():
    """
    Handle user input and verify the TOTP code.
    """
    user_input = entry.get()
    if verify_totp(user_input, SECRET_KEY):
        messagebox.showinfo("Verification", "TOTP verification successful! ✅")
        root.destroy()  # Close the GUI after successful verification
    else:
        messagebox.showerror("Verification", "TOTP verification failed. ❌")


# Create the GUI
root = tk.Tk()
root.title("TOTP Generator and Verifier")
root.geometry("400x300")
root.resizable(False, False)

# TOTP Display
totp_label = tk.Label(root, text="TOTP Code: ", font=("Arial", 16))
totp_label.pack(pady=20)

# Countdown Timer
timer_label = tk.Label(root, text="Time Remaining: ", font=("Arial", 14), fg="blue")
timer_label.pack(pady=10)

# User Input
entry_label = tk.Label(root, text="Enter TOTP Code:", font=("Arial", 12))
entry_label.pack(pady=10)

entry = tk.Entry(root, font=("Arial", 14), justify="center")
entry.pack(pady=5)

# Submit Button
submit_button = tk.Button(root, text="Verify", font=("Arial", 12), command=submit_code)
submit_button.pack(pady=20)

# Start the TOTP updater
update_totp()

# Run the GUI event loop
root.mainloop()
