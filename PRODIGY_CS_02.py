import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image

class ImageEncryptDecryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption & Decryption")

        # Variables for paths and key
        self.input_image_path = ""
        self.output_encrypted_image_path = ""
        self.output_decrypted_image_path = ""
        self.encryption_key = None

        # Widgets
        self.label_input = tk.Label(root, text="Input Image:")
        self.label_input.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.entry_input = tk.Entry(root, width=50)
        self.entry_input.grid(row=0, column=1, padx=10, pady=5)

        self.button_browse_input = tk.Button(root, text="Browse", command=self.browse_input)
        self.button_browse_input.grid(row=0, column=2, padx=10, pady=5)

        self.label_output_encrypted = tk.Label(root, text="Encrypted Image Output:")
        self.label_output_encrypted.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.entry_output_encrypted = tk.Entry(root, width=50)
        self.entry_output_encrypted.grid(row=1, column=1, padx=10, pady=5)

        self.button_browse_output_encrypted = tk.Button(root, text="Browse", command=self.browse_output_encrypted)
        self.button_browse_output_encrypted.grid(row=1, column=2, padx=10, pady=5)

        self.label_output_decrypted = tk.Label(root, text="Decrypted Image Output:")
        self.label_output_decrypted.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        self.entry_output_decrypted = tk.Entry(root, width=50)
        self.entry_output_decrypted.grid(row=2, column=1, padx=10, pady=5)

        self.button_browse_output_decrypted = tk.Button(root, text="Browse", command=self.browse_output_decrypted)
        self.button_browse_output_decrypted.grid(row=2, column=2, padx=10, pady=5)

        self.label_key = tk.Label(root, text="Encryption Key:")
        self.label_key.grid(row=3, column=0, padx=10, pady=5, sticky="w")

        self.entry_key = tk.Entry(root, width=20)
        self.entry_key.grid(row=3, column=1, padx=10, pady=5)

        self.button_encrypt = tk.Button(root, text="Encrypt", command=self.encrypt_image)
        self.button_encrypt.grid(row=4, column=1, padx=10, pady=10)

        self.button_decrypt = tk.Button(root, text="Decrypt", command=self.decrypt_image)
        self.button_decrypt.grid(row=5, column=1, padx=10, pady=10)

    def browse_input(self):
        self.input_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        self.entry_input.delete(0, tk.END)
        self.entry_input.insert(0, self.input_image_path)

    def browse_output_encrypted(self):
        self.output_encrypted_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg;*.jpeg")])
        self.entry_output_encrypted.delete(0, tk.END)
        self.entry_output_encrypted.insert(0, self.output_encrypted_image_path)

    def browse_output_decrypted(self):
        self.output_decrypted_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg;*.jpeg")])
        self.entry_output_decrypted.delete(0, tk.END)
        self.entry_output_decrypted.insert(0, self.output_decrypted_image_path)

    def encrypt_image(self):
        self.input_image_path = self.entry_input.get()
        self.output_encrypted_image_path = self.entry_output_encrypted.get()
        self.encryption_key = self.entry_key.get()

        if not self.input_image_path or not self.output_encrypted_image_path or not self.encryption_key:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        try:
            key = int(self.encryption_key)
        except ValueError:
            messagebox.showerror("Error", "Encryption key must be an integer.")
            return

        try:
            img = Image.open(self.input_image_path)
            img = img.convert("RGB")  # Ensure image is in RGB mode
            width, height = img.size
            pixels = img.load()

            for x in range(width):
                for y in range(height):
                    r, g, b = pixels[x, y]
                    r = r ^ key
                    g = g ^ key
                    b = b ^ key
                    pixels[x, y] = (r, g, b)

            img.save(self.output_encrypted_image_path)
            messagebox.showinfo("Success", "Image encrypted and saved.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def decrypt_image(self):
        self.output_encrypted_image_path = self.entry_output_encrypted.get()
        self.output_decrypted_image_path = self.entry_output_decrypted.get()
        self.encryption_key = self.entry_key.get()

        if not self.output_encrypted_image_path or not self.output_decrypted_image_path or not self.encryption_key:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        try:
            key = int(self.encryption_key)
        except ValueError:
            messagebox.showerror("Error", "Encryption key must be an integer.")
            return

        try:
            img = Image.open(self.output_encrypted_image_path)
            img = img.convert("RGB")  # Ensure image is in RGB mode
            width, height = img.size
            pixels = img.load()

            for x in range(width):
                for y in range(height):
                    r, g, b = pixels[x, y]
                    r = r ^ key
                    g = g ^ key
                    b = b ^ key
                    pixels[x, y] = (r, g, b)

            img.save(self.output_decrypted_image_path)
            messagebox.showinfo("Success", "Image decrypted and saved.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptDecryptApp(root)
    root.mainloop()
