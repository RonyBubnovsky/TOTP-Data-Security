import hmac
import hashlib
import time
import base64
import struct
import tkinter as tk
from tkinter import ttk, messagebox

# Shared Secret Key (Base32-encoded)
SECRET_KEY = "JBSWY3DPEHPK3PXP"  # Example secret key
current_details = {}  # Stores current generation details

def generate_totp(secret_key, time_step=30, digits=6, current_time=None):
    """Generate TOTP code with detailed intermediate steps"""
    if current_time is None:
        current_time = int(time.time())

    # Decode Base32 secret
    key = base64.b32decode(secret_key)
    
    # Calculate time counter
    time_counter = current_time // time_step
    time_bytes = struct.pack(">Q", time_counter)
    
    # Generate HMAC-SHA1
    hmac_hash = hmac.new(key, time_bytes, hashlib.sha1).digest()
    
    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    truncated_hash = hmac_hash[offset:offset+4]
    
    # Convert to integer and final code
    code = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
    totp_code = code % (10 ** digits)

    return {
        "secret_base32": secret_key,
        "secret_bytes": key.hex().upper(),
        "time_counter": time_counter,
        "time_bytes": time_bytes.hex().upper(),
        "hmac_sha1": hmac_hash.hex().upper(),
        "offset": offset,
        "truncated": truncated_hash.hex().upper(),
        "code_int": code,
        "final_code": str(totp_code).zfill(digits),
        "current_time": current_time,
        "time_remaining": time_step - (current_time % time_step)
    }

def verify_code(user_input, secret_key=SECRET_KEY, window_size=1, time_step=30):
    """
    Verify TOTP code with time window tolerance
    
    Args:
        user_input (str): The code entered by the user
        secret_key (str): Base32 encoded secret key
        window_size (int): Number of time steps to check before/after current time
        time_step (int): Time step in seconds (default 30)
    
    Returns:
        bool: True if verification successful, False otherwise
    """
    if not user_input.isdigit():
        return False
        
    current_time = int(time.time())
    
    # Check codes in time window
    for time_offset in range(-window_size, window_size + 1):
        # Calculate time for this window
        check_time = current_time + (time_offset * time_step)
        
        # Generate TOTP details for this time
        window_totp = generate_totp(
            secret_key=secret_key,
            time_step=time_step,
            current_time=check_time
        )
        
        # Constant time comparison to prevent timing attacks
        if hmac.compare_digest(
            user_input.encode('utf-8'),
            window_totp['final_code'].encode('utf-8')
        ):
            return True
        
    print("verified")
            
    return False

def update_interface():
    """Update both TOTP display and generation details"""
    global current_details
    current_details = generate_totp(SECRET_KEY)
    
    # Update main tab
    main_totp_label.config(text=f"TOTP Code: {current_details['final_code']}")
    main_timer_label.config(text=f"Time Remaining: {current_details['time_remaining']}s")
    
    # Update details tab
    details_vars['secret_base32'].set(current_details['secret_base32'])
    details_vars['secret_bytes'].set(current_details['secret_bytes'])
    details_vars['time_counter'].set(current_details['time_counter'])
    details_vars['time_bytes'].set(current_details['time_bytes'])
    details_vars['hmac_sha1'].set(current_details['hmac_sha1'])
    details_vars['offset'].set(current_details['offset'])
    details_vars['truncated'].set(current_details['truncated'])
    details_vars['code_int'].set(current_details['code_int'])
    details_vars['final_code'].set(current_details['final_code'])
    
    root.after(200, update_interface)

def handle_verification():
    """Handle verification UI interaction"""
    user_input = main_entry.get().strip()
    
    if verify_code(user_input, window_size=1):
        messagebox.showinfo("Success", "Verification successful! ✅")
        root.destroy()
    else:
        messagebox.showerror("Error", "Verification failed ❌")

def test_with_rfc_vectors():
    """Test with RFC 6238 test vectors"""
    test_vectors = [
        {
            "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "time": 59,
            "digits": 8,
            "expected": "94287082"
        },
        {
            "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "time": 1111111109,
            "digits": 8,
            "expected": "07081804"
        },
        {
            "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "time": 2000000000,
            "digits": 8,
            "expected": "69279037"
        }
    ]

    results = []
    for vector in test_vectors:
        generated = generate_totp(
            vector["secret"],
            digits=vector["digits"],
            current_time=vector["time"]
        )['final_code']
        results.append(
            f"Time: {vector['time']}\n"
            f"Expected: {vector['expected']}\n"
            f"Generated: {generated}\n"
            f"Status: {'PASS' if generated == vector['expected'] else 'FAIL'}\n"
        )
    
    messagebox.showinfo("RFC 6238 Test Results", "\n".join(results))

# Create main window
root = tk.Tk()
root.title("TOTP Authenticator")
root.geometry("800x650")

# Create tabbed interface
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# Main Tab ---------------------------------------------------------------
main_tab = ttk.Frame(notebook)
notebook.add(main_tab, text="Main")

# TOTP Display
main_totp_label = tk.Label(main_tab, font=("Arial", 24, "bold"))
main_totp_label.pack(pady=20)

# Timer Display
main_timer_label = tk.Label(main_tab, font=("Arial", 14), fg="blue")
main_timer_label.pack(pady=10)

# Verification Section
tk.Label(main_tab, text="Enter TOTP Code:", font=("Arial", 12)).pack(pady=5)
main_entry = tk.Entry(main_tab, font=("Arial", 14), justify="center")
main_entry.pack(pady=5)
tk.Button(main_tab, text="Verify", font=("Arial", 12), 
         command=handle_verification).pack(pady=10)

# Test Button
tk.Button(main_tab, text="Test RFC Vectors", font=("Arial", 10),
          command=test_with_rfc_vectors).pack(pady=5)

# Details Tab -------------------------------------------------------------
details_tab = ttk.Frame(notebook)
notebook.add(details_tab, text="Generation Steps")

# Create detail fields
details_vars = {}
fields = [
    ("Secret Key (Base32)", "secret_base32"),
    ("Decoded Secret (Hex)", "secret_bytes"),
    ("Time Counter", "time_counter"),
    ("Time Bytes (Hex)", "time_bytes"),
    ("HMAC-SHA1 Hash (Hex)", "hmac_sha1"),
    ("Offset Value", "offset"),
    ("Truncated Hash (Hex)", "truncated"),
    ("Intermediate Code", "code_int"),
    ("Final 6-digit Code", "final_code")
]

for row, (label_text, var_name) in enumerate(fields):
    frame = ttk.Frame(details_tab)
    frame.grid(row=row, column=0, sticky="ew", padx=10, pady=2)
    
    label = ttk.Label(frame, text=label_text, width=20, anchor="w")
    label.pack(side="left")
    
    details_vars[var_name] = tk.StringVar()
    entry = ttk.Entry(frame, textvariable=details_vars[var_name], 
                     width=60, state="readonly")
    entry.pack(side="left", fill="x", expand=True)

# Start updates
update_interface()

# Run main loop
root.mainloop()