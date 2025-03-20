# 🔐 Advanced Caesar Cipher Encryption Tool

A Python-based CLI tool combining Caesar Cipher encryption with text and image steganography. Features a neon-colored interface, file encryption, and robust error handling. Ideal for learning cryptography and steganography concepts.

---

## 🚀 Features
✅ **Caesar Cipher Encryption/Decryption:** Encrypts text/files with a dynamic shift based on a key.  
✅ **Text Steganography:** Hides messages in visible characters (e.g., spaces, dots).  
✅ **Image Steganography:** Embeds text in images using LSB (Least Significant Bit) technique.  
✅ **Animated Neon CLI:** Engaging interface with vibrant visuals.  
✅ **File Encryption/Decryption:** Ensures secure data handling with `.enc`/`.dec` output.  
✅ **Hexadecimal Output:** Provides encrypted text in both text and hex format.  
✅ **Self-Destruct Mode:** Program locks after 3 incorrect decryption attempts.  

---

## 📋 Prerequisites
- Python 3.8 or higher  
- Supported image formats: `.png` (recommended), `.jpg`, `.jpeg`, `.bmp`  
- Maximum text length for image steganography depends on image size (width × height × 3 bits)  

---

## 💻 Installation

1. **Clone the Repository:**
```bash
git clone https://github.com/your-username/caesar-cipher-tool.git
cd caesar-cipher-tool
```

2. **Install Dependencies:**
```bash
pip install -r requirements.txt
```
_The script auto-installs missing packages on first run if needed._

---

## 🟡 Usage

1. **Run the Tool:**
```bash
python caesar_cipher.py
```

2. **Menu Options:**
- `1. Encrypt Text`: Encrypt text with a key.  
- `2. Decrypt Text`: Decrypt text with the correct key.  
- `3. Steganographic Encode (Text)`: Hide text in visible characters.  
- `4. Steganographic Decode (Text)`: Reveal hidden text.  
- `5. Encrypt File`: Encrypt a file’s contents.  
- `6. Decrypt File`: Decrypt an encrypted file.  
- `7. Image Steganographic Encode`: Hide text in an image.  
- `8. Image Steganographic Decode`: Extract text from an image.  
- `9. Exit`: Quit the program.  

3. **Examples:**
- Encrypt text:
```
Select an option: 1
Enter encryption key: mykey
Enter text to encrypt: Hello World
Encrypted: Ifmmp Xpsme
Hex: 49666d6d70205870736d65
```

- Hide text in image:
```
Select an option: 7
Enter text to hide in image: Secret Message
Enter input image path: cover.png
Enter output stego image path: stego.png
Steganographic image saved as stego.png
```

- Decrypt file:
```
Select an option: 6
Enter filename to decrypt: data.txt.enc
Enter decryption key: mykey
Decrypted file saved as data.txt.dec
```

---

## 🧩 How It Works
- **Caesar Cipher:** Uses a key to generate dynamic shifts for each character, preserving case and non-alpha chars.  
- **Text Steganography:** Converts text to binary, maps to visible characters (e.g., space = 00, dot = 01).  
- **Image Steganography:** Embeds binary text in the LSB of RGB channels, adds an end marker (`00000000`).  

---

## ❗ Important Notes
✅ **Key:** Required for encryption/decryption; must match for decryption or it fails after 3 attempts.  
✅ **Image Stego:** Use PNG for lossless encoding; text length must fit image capacity.  
✅ **Termination:** Press `Ctrl+C` to cancel operations or exit gracefully.  
✅ **File Output:** Encrypted files get `.enc`, decrypted get `.dec`.  

---

## 🛠️ Troubleshooting
- **Module Not Found:** Ensure `requirements.txt` packages are installed.  
- **Image Error:** Check file path and format (PNG preferred).  
- **Text Too Large:** Reduce text length or use a larger image for steganography.  

---

## 📝 License
This project is licensed under the **MIT License**.

💬 _Developed by Ashok (Nickname: NeospectraX). Contributions are welcome!_