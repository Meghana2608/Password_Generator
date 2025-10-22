import random
import string
import tkinter as tk
from tkinter import messagebox

def generate_password(length, use_uppercase, use_lowercase, use_numbers, use_symbols):
    # Define character sets based on user criteria
    characters = ""
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_numbers:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation
    
    # Ensure at least one character set must be selected
    if not characters:
        raise ValueError("At least one character set must be selected.")
    
    # Generate password by randomly selecting characters
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def on_generate():
    try:
        length = int(length_entry.get())
        if length <= 0:
            raise ValueError("Length must be a positive integer.")
        
        use_uppercase = uppercase_var.get()
        use_lowercase = lowercase_var.get()
        use_numbers = numbers_var.get()
        use_symbols = symbols_var.get()
        
        password = generate_password(length, use_uppercase, use_lowercase, use_numbers, use_symbols)
        result_label.config(text=f"Generated Password: {password}")
        copy_button.config(state="normal")  # Enable copy button
        regenerate_button.config(state="normal")  # Enable regenerate button
    
    except ValueError as e:
        messagebox.showerror("Error", str(e))
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")

def on_copy():
    password_text = result_label.cget("text").replace("Generated Password: ", "")
    if password_text:
        root.clipboard_clear()
        root.clipboard_append(password_text)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("No Password", "Generate a password first.")

def on_regenerate():
    on_generate()  # Reuse the generate function

# Create the main window with elegant purple/blue theme
root = tk.Tk()
root.title("Password Generator")
root.geometry("450x400")
root.configure(bg="#f3e5f5")  # Soft lavender purple background

# Frame for inputs
input_frame = tk.Frame(root, bg="#f3e5f5", padx=20, pady=10)
input_frame.pack(fill="x")

# Length input
tk.Label(input_frame, text="Password Length:", bg="#f3e5f5", fg="#4a148c", font=("Arial", 10, "bold")).pack(anchor="w")
length_entry = tk.Entry(input_frame, font=("Arial", 10), bg="#ffffff", fg="#000000")
length_entry.pack(fill="x", pady=5)
length_entry.insert(0, "12")  # Default value

# Checkboxes for criteria
uppercase_var = tk.BooleanVar(value=True)
lowercase_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=False)

tk.Checkbutton(input_frame, text="Include Uppercase Letters", variable=uppercase_var, bg="#f3e5f5", fg="#4a148c", font=("Arial", 9)).pack(anchor="w")
tk.Checkbutton(input_frame, text="Include Lowercase Letters", variable=lowercase_var, bg="#f3e5f5", fg="#4a148c", font=("Arial", 9)).pack(anchor="w")
tk.Checkbutton(input_frame, text="Include Numbers", variable=numbers_var, bg="#f3e5f5", fg="#4a148c", font=("Arial", 9)).pack(anchor="w")
tk.Checkbutton(input_frame, text="Include Symbols", variable=symbols_var, bg="#f3e5f5", fg="#4a148c", font=("Arial", 9)).pack(anchor="w")

# Frame for buttons
button_frame = tk.Frame(root, bg="#f3e5f5", pady=10)
button_frame.pack()

# Generate button (purple)
generate_button = tk.Button(button_frame, text="Generate Password", command=on_generate, bg="#9c27b0", fg="#ffffff", font=("Arial", 10, "bold"), padx=10, pady=5)
generate_button.pack(side="left", padx=5)

# Regenerate button (indigo blue)
regenerate_button = tk.Button(button_frame, text="Regenerate", command=on_regenerate, bg="#3f51b5", fg="#ffffff", font=("Arial", 10, "bold"), padx=10, pady=5, state="disabled")
regenerate_button.pack(side="left", padx=5)

# Copy button (cyan blue)
copy_button = tk.Button(button_frame, text="Copy to Clipboard", command=on_copy, bg="#00bcd4", fg="#ffffff", font=("Arial", 10, "bold"), padx=10, pady=5, state="disabled")
copy_button.pack(side="left", padx=5)

# Result display (dark purple text for elegance)
result_label = tk.Label(root, text="", font=("Arial", 12, "bold"), bg="#f3e5f5", fg="#4a148c", wraplength=400, justify="center")
result_label.pack(pady=20)

# Run the application
root.mainloop()
