import hmac
import hashlib
import time
import base64
import struct
import tkinter as tk
from tkinter import ttk, messagebox

# Shared Secret Key (Base32-encoded) used for the main TOTP display.
# (This key is arbitrary and separate from the RFC test vectors.)
SECRET_KEY = "JBSWY3DPEHPK3PXP"

# Dictionary to store current TOTP generation details
current_details = {}

# Default hash algorithm for the main display
selected_algo = "SHA1"


def generate_totp(secret_key, time_step=30, digits=6, current_time=None, algo="SHA1"):
    """Generate a TOTP code using SHA-1, SHA-256, or SHA-512."""
    if current_time is None:
        current_time = int(time.time())

    # Decode the Base32 secret key
    key = base64.b32decode(secret_key)
    time_counter = current_time // time_step
    time_bytes = struct.pack(">Q", time_counter)

    # Select hashing algorithm based on algo parameter
    algo = algo.upper()
    if algo == "SHA256":
        hmac_hash = hmac.new(key, time_bytes, hashlib.sha256).digest()
    elif algo == "SHA512":
        hmac_hash = hmac.new(key, time_bytes, hashlib.sha512).digest()
    else:
        hmac_hash = hmac.new(key, time_bytes, hashlib.sha1).digest()

    # Dynamic truncation to obtain a 4-byte string
    offset = hmac_hash[-1] & 0x0F
    truncated_hash = hmac_hash[offset:offset + 4]
    code_int = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
    totp_code = code_int % (10 ** digits)

    return {
        "algo": algo,
        "secret_base32": secret_key,
        "secret_bytes": key.hex().upper(),
        "time_counter": time_counter,
        "time_bytes": time_bytes.hex().upper(),
        "hmac_hash": hmac_hash.hex().upper(),
        "offset": offset,
        "truncated": truncated_hash.hex().upper(),
        "code_int": code_int,
        "final_code": str(totp_code).zfill(digits),
        "current_time": current_time,
        "time_remaining": time_step - (current_time % time_step)
    }


def verify_code(user_input, secret_key=SECRET_KEY, window_size=1, time_step=30, algo="SHA1"):
    """Verify a TOTP code by checking a small time window."""
    if not user_input.isdigit():
        return False

    current_time = int(time.time())
    for time_offset in range(-window_size, window_size + 1):
        check_time = current_time + (time_offset * time_step)
        window_totp = generate_totp(secret_key, time_step, current_time=check_time, algo=algo)
        if hmac.compare_digest(user_input.encode('utf-8'), window_totp['final_code'].encode('utf-8')):
            return True
    return False


def update_interface():
    """Update the TOTP display and details tab."""
    global current_details
    current_details = generate_totp(SECRET_KEY, algo=selected_algo)

    main_totp_label.config(text=f"TOTP Code: {current_details['final_code']}")
    main_timer_label.config(text=f"Time Remaining: {current_details['time_remaining']}s")

    for key, var in details_vars.items():
        var.set(str(current_details.get(key, "")))

    root.after(200, update_interface)


def handle_verification():
    """Verify user-entered TOTP code."""
    user_input = main_entry.get().strip()
    if verify_code(user_input, algo=selected_algo):
        messagebox.showinfo("Success", "Verification successful! ✅")
        root.destroy()
    else:
        messagebox.showerror("Error", "Verification failed ❌")


def set_algorithm(*args):
    """Update the selected hash algorithm."""
    global selected_algo
    selected_algo = algo_var.get()


def test_with_rfc_vectors():
    """
    Test using RFC 6238 test vectors.
    For each algorithm (SHA1, SHA256, SHA512), we test six different times.
    
    The secrets (in ASCII) are:
      - SHA1:   "12345678901234567890" (20 bytes)
      - SHA256: "12345678901234567890123456789012" (32 bytes)
      - SHA512: "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
    
    They are Base32-encoded before being passed to generate_totp.
    """
    test_vectors = [
        # Time = 59 seconds (T = 1)
        {"time": 59, "algo": "SHA1",
         "secret": base64.b32encode(b"12345678901234567890").decode('utf-8'),
         "expected": "94287082", "digits": 8},
        {"time": 59, "algo": "SHA256",
         "secret": base64.b32encode(b"12345678901234567890123456789012").decode('utf-8'),
         "expected": "46119246", "digits": 8},
        {"time": 59, "algo": "SHA512",
         "secret": base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode('utf-8'),
         "expected": "90693936", "digits": 8},

        # Time = 1111111109 (2005-03-18 01:58:29 UTC; T = 0x00000000023523EC)
        {"time": 1111111109, "algo": "SHA1",
         "secret": base64.b32encode(b"12345678901234567890").decode('utf-8'),
         "expected": "07081804", "digits": 8},
        {"time": 1111111109, "algo": "SHA256",
         "secret": base64.b32encode(b"12345678901234567890123456789012").decode('utf-8'),
         "expected": "68084774", "digits": 8},
        {"time": 1111111109, "algo": "SHA512",
         "secret": base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode('utf-8'),
         "expected": "25091201", "digits": 8},

        # Time = 1111111111 (2005-03-18 01:58:31 UTC; T = 0x00000000023523ED)
        {"time": 1111111111, "algo": "SHA1",
         "secret": base64.b32encode(b"12345678901234567890").decode('utf-8'),
         "expected": "14050471", "digits": 8},
        {"time": 1111111111, "algo": "SHA256",
         "secret": base64.b32encode(b"12345678901234567890123456789012").decode('utf-8'),
         "expected": "67062674", "digits": 8},
        {"time": 1111111111, "algo": "SHA512",
         "secret": base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode('utf-8'),
         "expected": "99943326", "digits": 8},

        # Time = 1234567890 (2009-02-13 23:31:30 UTC; T = 0x000000000273EF07)
        {"time": 1234567890, "algo": "SHA1",
         "secret": base64.b32encode(b"12345678901234567890").decode('utf-8'),
         "expected": "89005924", "digits": 8},
        {"time": 1234567890, "algo": "SHA256",
         "secret": base64.b32encode(b"12345678901234567890123456789012").decode('utf-8'),
         "expected": "91819424", "digits": 8},
        {"time": 1234567890, "algo": "SHA512",
         "secret": base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode('utf-8'),
         "expected": "93441116", "digits": 8},

        # Time = 2000000000 (2033-05-18 03:33:20 UTC; T = 0x0000000003F940AA)
        {"time": 2000000000, "algo": "SHA1",
         "secret": base64.b32encode(b"12345678901234567890").decode('utf-8'),
         "expected": "69279037", "digits": 8},
        {"time": 2000000000, "algo": "SHA256",
         "secret": base64.b32encode(b"12345678901234567890123456789012").decode('utf-8'),
         "expected": "90698825", "digits": 8},
        {"time": 2000000000, "algo": "SHA512",
         "secret": base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode('utf-8'),
         "expected": "38618901", "digits": 8},

        # Time = 20000000000 (2603-10-11 11:33:20 UTC; T = 0x0000000027BC86AA)
        {"time": 20000000000, "algo": "SHA1",
         "secret": base64.b32encode(b"12345678901234567890").decode('utf-8'),
         "expected": "65353130", "digits": 8},
        {"time": 20000000000, "algo": "SHA256",
         "secret": base64.b32encode(b"12345678901234567890123456789012").decode('utf-8'),
         "expected": "77737706", "digits": 8},
        {"time": 20000000000, "algo": "SHA512",
         "secret": base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode('utf-8'),
         "expected": "47863826", "digits": 8},
    ]

    results = []
    for vector in test_vectors:
        generated = generate_totp(
            vector["secret"],
            digits=vector["digits"],
            current_time=vector["time"],
            algo=vector["algo"]
        )['final_code']
        result = (
            f"Time: {vector['time']} | Algo: {vector['algo']}\n"
            f"Expected: {vector['expected']} | Generated: {generated}\n"
            f"Status: {'PASS ✅' if generated == vector['expected'] else 'FAIL ❌'}\n"
        )
        results.append(result)
        # Also print each result to the terminal
        print(result)

    messagebox.showinfo("RFC 6238 Test Results", "\n".join(results))


# --------------------
# GUI Setup using tkinter
# --------------------
root = tk.Tk()
root.title("TOTP Authenticator")
root.geometry("800x650")

notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# Main Tab
main_tab = ttk.Frame(notebook)
notebook.add(main_tab, text="Main")

main_totp_label = tk.Label(main_tab, font=("Arial", 24, "bold"))
main_totp_label.pack(pady=20)

main_timer_label = tk.Label(main_tab, font=("Arial", 14), fg="blue")
main_timer_label.pack(pady=10)

algo_var = tk.StringVar(value="SHA1")
tk.Label(main_tab, text="Select Hash Algorithm:", font=("Arial", 12)).pack(pady=5)
algo_dropdown = ttk.Combobox(main_tab, textvariable=algo_var, values=["SHA1", "SHA256", "SHA512"], state="readonly")
algo_dropdown.pack(pady=5)
algo_dropdown.bind("<<ComboboxSelected>>", set_algorithm)

tk.Label(main_tab, text="Enter TOTP Code:", font=("Arial", 12)).pack(pady=5)
main_entry = tk.Entry(main_tab, font=("Arial", 14), justify="center")
main_entry.pack(pady=5)
tk.Button(main_tab, text="Verify", font=("Arial", 12), command=handle_verification).pack(pady=10)
tk.Button(main_tab, text="Test RFC Vectors", font=("Arial", 10), command=test_with_rfc_vectors).pack(pady=5)

# Details Tab (showing generation steps)
details_tab = ttk.Frame(notebook)
notebook.add(details_tab, text="Generation Steps")

details_vars = {}
fields = [
    ("Algorithm", "algo"),
    ("Secret Key (Base32)", "secret_base32"),
    ("Decoded Secret (Hex)", "secret_bytes"),
    ("Time Counter", "time_counter"),
    ("Time Bytes (Hex)", "time_bytes"),
    ("HMAC Hash (Hex)", "hmac_hash"),
    ("Offset Value", "offset"),
    ("Truncated Hash (Hex)", "truncated"),
    ("Intermediate Code", "code_int"),
    ("Final Code", "final_code")
]

for row, (label_text, var_name) in enumerate(fields):
    frame = ttk.Frame(details_tab)
    frame.grid(row=row, column=0, sticky="ew", padx=10, pady=2)
    ttk.Label(frame, text=label_text, width=20, anchor="w").pack(side="left")
    details_vars[var_name] = tk.StringVar()
    ttk.Entry(frame, textvariable=details_vars[var_name], width=60, state="readonly").pack(side="left", fill="x", expand=True)

update_interface()
root.mainloop()
