import sys
import os
import random
import string
import binascii
import time
from getpass import getpass

# Handle imports with better error handling
try:
    from stegano import lsb  # type: ignore
    from PIL import Image  # type: ignore
except ImportError:
    print("Installing required packages...")
    os.system('pip install stegano==0.11.5 Pillow')
    try:
        from stegano import lsb  # type: ignore
        from PIL import Image  # type: ignore
    except ImportError:
        print("Failed to install required packages. Please install manually:")
        print("pip install stegano==0.11.5 Pillow")
        sys.exit(1)

# ANSI color codes for terminal output
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_BLUE = "\033[34m"
COLOR_CYAN = "\033[36m"
COLOR_PURPLE = "\033[95m"  # Neon purple
COLOR_PINK = "\033[91m"    # Neon pink
COLOR_BRIGHT_GREEN = "\033[92m"  # Neon green
COLOR_BRIGHT_YELLOW = "\033[93m"  # Neon yellow
COLOR_BRIGHT_BLUE = "\033[94m"   # Neon blue
COLOR_BRIGHT_CYAN = "\033[96m"   # Neon cyan

# Enhanced ASCII Banner with Animation
def display_banner():
    neon_colors = [COLOR_PURPLE, COLOR_PINK, COLOR_BRIGHT_GREEN, COLOR_BRIGHT_YELLOW, COLOR_BRIGHT_BLUE, COLOR_BRIGHT_CYAN]
    banner = f"""
{neon_colors[0]}   ██████╗ █████╗ ███████╗███████╗ █████╗ ██████╗ ███████╗{COLOR_RESET}
{neon_colors[1]}  ██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝{COLOR_RESET}
{neon_colors[2]}  ██║     ███████║█████╗  █████╗  ███████║██████╔╝█████╗  {COLOR_RESET}
{neon_colors[3]}  ██║     ██╔══██║██╔══╝  ██╔══╝  ██╔══██║██╔══██╗██╔══╝  {COLOR_RESET}
{neon_colors[4]}  ╚██████╗██║  ██║███████╗███████╗██║  ██║██║  ██║███████╗{COLOR_RESET}
{neon_colors[5]}   ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝{COLOR_RESET}
{COLOR_YELLOW}       Advanced Caesar Cipher Encryption Tool v1.0{COLOR_RESET}
    """
    # Simple animation effect
    for i in range(len(banner)):
        sys.stdout.write(banner[i])
        sys.stdout.flush()
        time.sleep(0.01)  # Slow typing effect
    print()
    # Display developer credit
    print(f"{COLOR_CYAN}{'─' * 50}{COLOR_RESET}")
    print(f"{COLOR_BRIGHT_YELLOW}      Developed by Ashok (Nickname: NeospectraX){COLOR_RESET}")
    print(f"{COLOR_CYAN}{'─' * 50}{COLOR_RESET}\n")

# Visible characters for text steganography (for testing; you can switch back to invisible chars if needed)
VISIBLE_CHARS = [' ', '.', '-', '+']

class CaesarCipher:
    def __init__(self, key=None):  # Default key to None for steganography
        self.key = key
        self.attempts = 3
        if key:
            random.seed(key)

    def generate_shift(self, position, message_len):
        if self.key:
            base_shift = (ord(self.key[position % len(self.key)]) + message_len) % 26
            return base_shift if base_shift != 0 else 1
        return 0  # Default shift for steganography (not used here)

    def encrypt(self, plaintext):
        if not self.key:
            raise ValueError("Encryption requires a key")
        encrypted = ""
        for i, char in enumerate(plaintext):
            if char.isalpha():
                shift = self.generate_shift(i, len(plaintext))
                base = ord('A') if char.isupper() else ord('a')
                encrypted += chr((ord(char) - base + shift) % 26 + base)
            else:
                encrypted += char
        return encrypted

    def decrypt(self, ciphertext, provided_key):
        if not self.key or provided_key != self.key:
            self.attempts -= 1
            if self.attempts <= 0:
                print(f"{COLOR_RED}Too many incorrect attempts. Self-destructing...{COLOR_RESET}")
                sys.exit(1)
            return None
        decrypted = ""
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                shift = self.generate_shift(i, len(ciphertext))
                base = ord('A') if char.isupper() else ord('a')
                decrypted += chr((ord(char) - base - shift) % 26 + base)
            else:
                decrypted += char
        return decrypted

    def to_hex(self, text):
        return binascii.hexlify(text.encode()).decode()

    def stegano_encrypt(self, text):
        binary = ''.join(format(ord(c), '08b') for c in text)
        hidden = ''.join(VISIBLE_CHARS[int(binary[i:i+2], 2)] for i in range(0, len(binary), 2))
        print(f"{COLOR_CYAN}Raw hidden characters (for debugging): {hidden}{COLOR_RESET}")
        return f" {COLOR_YELLOW}[hidden in whitespace]{COLOR_RESET}" + hidden + f"{COLOR_YELLOW}[end]{COLOR_RESET} "

    def stegano_decrypt(self, text):
        # Remove color codes and extract just the hidden part
        clean_text = text.replace(COLOR_YELLOW, "").replace(COLOR_RESET, "")
        hidden_part = clean_text.replace("[hidden in whitespace]", "").replace("[end]", "").strip()
        binary = ""
        for char in hidden_part:
            if char in VISIBLE_CHARS:
                binary += format(VISIBLE_CHARS.index(char), '02b')
        if len(binary) % 8 != 0:
            binary = binary + '0' * (8 - (len(binary) % 8))  # Pad with zeros if needed
        chars = [chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)]
        return ''.join(chars)

    def image_stegano_encrypt(self, text, input_image_path, output_image_path):
        # Open the input image and convert to RGB (PNG recommended for lossless)
        img = Image.open(input_image_path).convert('RGB')
        width, height = img.size
        pixels = list(img.getdata())

        # Convert text to binary and add an end marker (8 zeros)
        binary = ''.join(format(ord(c), '08b') for c in text) + '00000000'  # End marker
        if len(binary) > width * height * 3:  # Each pixel has 3 channels (RGB)
            raise ValueError("Text too large to hide in the image")

        # Embed binary data using LSB (Least Significant Bit) in RGB channels
        binary_index = 0
        new_pixels = []
        for i in range(len(pixels)):
            r, g, b = pixels[i]
            if binary_index < len(binary):
                # Modify the least significant bit of each channel
                r = (r & 0xFE) | int(binary[binary_index])
                binary_index += 1
                if binary_index < len(binary):
                    g = (g & 0xFE) | int(binary[binary_index])
                    binary_index += 1
                if binary_index < len(binary):
                    b = (b & 0xFE) | int(binary[binary_index])
                    binary_index += 1
            new_pixels.append((r, g, b))

        # Create a new image with the modified pixels
        new_img = Image.new('RGB', (width, height))
        new_img.putdata(new_pixels)
        new_img.save(output_image_path, 'PNG')  # Force PNG for lossless saving
        print(f"{COLOR_GREEN}Steganographic image saved as {output_image_path}{COLOR_RESET}")

    def image_stegano_decrypt(self, input_image_path):
        # Open the stego image and convert to RGB
        img = Image.open(input_image_path).convert('RGB')
        pixels = list(img.getdata())

        # Extract binary data from LSB of RGB channels
        binary = ""
        max_bits = 100000  # Limit to prevent infinite loops or large noise
        for r, g, b in pixels[:max_bits // 3]:  # Limit to avoid excessive processing
            binary += str(r & 1)  # LSB of red
            binary += str(g & 1)  # LSB of green
            binary += str(b & 1)  # LSB of blue
            if len(binary) >= 8 and binary[-8:] == "00000000":  # Check for end marker
                break

        # Convert binary to text, stopping at the end marker
        text = ""
        for i in range(0, len(binary) - 8, 8):  # Stop before the end marker
            byte = binary[i:i+8]
            if byte == "00000000":  # Stop at end marker
                break
            text += chr(int(byte, 2))
        if not text:
            raise ValueError("No valid text found in the image or image corrupted")
        return text

def process_file(filename, key, mode):
    if not key:
        print(f"{COLOR_RED}Key is required for encryption/decryption!{COLOR_RESET}")
        return
    cipher = CaesarCipher(key)
    try:
        print(f"{COLOR_BLUE}Processing file: {filename}{COLOR_RESET}")
        with open(filename, 'r') as f:
            content = f.read()
        if mode == 'encrypt':
            result = cipher.encrypt(content)
            with open(filename + '.enc', 'w') as f:
                f.write(result)
            print(f"{COLOR_GREEN}Encrypted file saved as {filename}.enc{COLOR_RESET}")
            print(f"{COLOR_YELLOW}Hex: {cipher.to_hex(result)}{COLOR_RESET}")
        elif mode == 'decrypt':
            result = cipher.decrypt(content, key)
            if result:
                with open(filename + '.dec', 'w') as f:
                    f.write(result)
                print(f"{COLOR_GREEN}Decrypted file saved as {filename}.dec{COLOR_RESET}")
                print(f"{COLOR_YELLOW}Hex: {cipher.to_hex(result)}{COLOR_RESET}")
            else:
                print(f"{COLOR_RED}Incorrect key!{COLOR_RESET}")
    except FileNotFoundError:
        print(f"{COLOR_RED}File not found!{COLOR_RESET}")

def get_input_with_keyboard_interrupt_handling(prompt):
    """Wrapper to handle keyboard interrupts during input"""
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print(f"\n{COLOR_RED}Operation cancelled by user. Returning to menu...{COLOR_RESET}")
        return None

def get_password_with_keyboard_interrupt_handling(prompt):
    """Wrapper to handle keyboard interrupts during password input"""
    try:
        return getpass(prompt)
    except KeyboardInterrupt:
        print(f"\n{COLOR_RED}Operation cancelled by user. Returning to menu...{COLOR_RESET}")
        return None

def main():
    # Set up graceful keyboard interrupt handling for the entire program
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        display_banner()
        
        while True:
            try:
                # Add a decorative border around the menu
                menu_width = 50  # Width of the menu box
                print(f"{COLOR_CYAN}╔{'═' * menu_width}╗{COLOR_RESET}")
                print(f"{COLOR_CYAN}║{COLOR_RESET} {COLOR_YELLOW}1. Encrypt Text{COLOR_RESET}{' ' * (menu_width - 16)}{COLOR_CYAN}║{COLOR_RESET}")
                print(f"{COLOR_CYAN}║{COLOR_RESET} {COLOR_YELLOW}2. Decrypt Text{COLOR_RESET}{' ' * (menu_width - 16)}{COLOR_CYAN}║{COLOR_RESET}")
                print(f"{COLOR_CYAN}║{COLOR_RESET} {COLOR_YELLOW}3. Steganographic Encode (Text){COLOR_RESET}{' ' * (menu_width - 32)}{COLOR_CYAN}║{COLOR_RESET}")
                print(f"{COLOR_CYAN}║{COLOR_RESET} {COLOR_YELLOW}4. Steganographic Decode (Text){COLOR_RESET}{' ' * (menu_width - 32)}{COLOR_CYAN}║{COLOR_RESET}")
                print(f"{COLOR_CYAN}║{COLOR_RESET} {COLOR_YELLOW}5. Encrypt File{COLOR_RESET}{' ' * (menu_width - 16)}{COLOR_CYAN}║{COLOR_RESET}")
                print(f"{COLOR_CYAN}║{COLOR_RESET} {COLOR_YELLOW}6. Decrypt File{COLOR_RESET}{' ' * (menu_width - 16)}{COLOR_CYAN}║{COLOR_RESET}")
                print(f"{COLOR_CYAN}║{COLOR_RESET} {COLOR_YELLOW}7. Image Steganographic Encode{COLOR_RESET}{' ' * (menu_width - 31)}{COLOR_CYAN}║{COLOR_RESET}")
                print(f"{COLOR_CYAN}║{COLOR_RESET} {COLOR_YELLOW}8. Image Steganographic Decode{COLOR_RESET}{' ' * (menu_width - 31)}{COLOR_CYAN}║{COLOR_RESET}")
                print(f"{COLOR_CYAN}║{COLOR_RESET} {COLOR_GREEN}9. Exit{COLOR_RESET}{' ' * (menu_width - 8)}{COLOR_CYAN}║{COLOR_RESET}")
                print(f"{COLOR_CYAN}╚{'═' * menu_width}╝{COLOR_RESET}")
                
                choice = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Select an option: {COLOR_RESET}")
                if choice is None:
                    continue  # If keyboard interrupt happened, go back to menu
                
                # Initialize key as None for all paths
                key = None
                
                if choice in ['1', '2', '5', '6']:
                    key = get_password_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter encryption key: {COLOR_RESET}")
                    if key is None:
                        continue  # If keyboard interrupt happened, go back to menu
                    cipher = CaesarCipher(key)
                else:
                    cipher = CaesarCipher()  # Default instance for steganography (no key needed)

                if choice == '1':
                    text = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter text to encrypt: {COLOR_RESET}")
                    if text is None:
                        continue
                    encrypted = cipher.encrypt(text)
                    print(f"{COLOR_GREEN}Encrypted: {encrypted}{COLOR_RESET}")
                    print(f"{COLOR_YELLOW}Hex: {cipher.to_hex(encrypted)}{COLOR_RESET}")

                elif choice == '2':
                    text = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter text to decrypt: {COLOR_RESET}")
                    if text is None:
                        continue
                    
                    dec_key = get_password_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter decryption key: {COLOR_RESET}")
                    if dec_key is None:
                        continue
                        
                    decrypted = cipher.decrypt(text, dec_key)
                    if decrypted:
                        print(f"{COLOR_GREEN}Decrypted: {decrypted}{COLOR_RESET}")
                        print(f"{COLOR_YELLOW}Hex: {cipher.to_hex(decrypted)}{COLOR_RESET}")
                    else:
                        print(f"{COLOR_RED}Incorrect key!{COLOR_RESET}")

                elif choice == '3':
                    text = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter text to hide: {COLOR_RESET}")
                    if text is None:
                        continue
                    hidden = cipher.stegano_encrypt(text)
                    print(f"{COLOR_GREEN}Steganographic output: {hidden}{COLOR_RESET}")

                elif choice == '4':
                    text = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter text with hidden message: {COLOR_RESET}")
                    if text is None:
                        continue
                    revealed = cipher.stegano_decrypt(text)
                    print(f"{COLOR_GREEN}Revealed: {revealed}{COLOR_RESET}")

                elif choice == '5':
                    filename = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter filename to encrypt: {COLOR_RESET}")
                    if filename is None:
                        continue
                    if not key:  # Ensure key is defined
                        key = get_password_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter encryption key: {COLOR_RESET}")
                        if key is None:
                            continue
                    process_file(filename, key, 'encrypt')

                elif choice == '6':
                    filename = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter filename to decrypt: {COLOR_RESET}")
                    if filename is None:
                        continue
                    if not key:  # Ensure key is defined
                        key = get_password_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter decryption key: {COLOR_RESET}")
                        if key is None:
                            continue
                    process_file(filename, key, 'decrypt')

                elif choice == '7':
                    text = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter text to hide in image: {COLOR_RESET}")
                    if text is None:
                        continue
                    input_image = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter input image path (e.g., cover.png): {COLOR_RESET}")
                    if input_image is None:
                        continue
                    output_image = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter output stego image path (e.g., stego.png): {COLOR_RESET}")
                    if output_image is None:
                        continue
                    try:
                        cipher.image_stegano_encrypt(text, input_image, output_image)
                    except Exception as e:
                        print(f"{COLOR_RED}Error: {e}{COLOR_RESET}")

                elif choice == '8':
                    input_image = get_input_with_keyboard_interrupt_handling(f"{COLOR_BLUE}Enter stego image path (e.g., stego.png): {COLOR_RESET}")
                    if input_image is None:
                        continue
                    try:
                        revealed = cipher.image_stegano_decrypt(input_image)
                        print(f"{COLOR_GREEN}Revealed from image: {revealed}{COLOR_RESET}")
                    except Exception as e:
                        print(f"{COLOR_RED}Error: {e}{COLOR_RESET}")

                elif choice == '9':
                    print(f"{COLOR_RED}Exiting...{COLOR_RESET}")
                    sys.exit(0)
                else:
                    print(f"{COLOR_RED}Invalid option!{COLOR_RESET}")
                    
            except KeyboardInterrupt:
                # Handle Ctrl+C during menu navigation
                print(f"\n{COLOR_RED}Operation cancelled by user. Returning to menu...{COLOR_RESET}")
                continue
    
    except KeyboardInterrupt:
        # Handle Ctrl+C at program level
        print(f"\n{COLOR_RED}Program terminated by user.{COLOR_RESET}")
        sys.exit(0)
    except Exception as e:
        # Handle other exceptions at program level
        print(f"\n{COLOR_RED}An unexpected error occurred: {str(e)}{COLOR_RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()