#!/usr/bin/env python3
"""
SHADOW PASSWORD CRACKER - ADVANCED VERSION
Author: Shadow Core
Description: Advanced MD5 hash cracking dengan XOR decryption
"""

import hashlib
import sys
import os
import time
from pathlib import Path
from datetime import datetime

def setup_terminal():
    """Setup terminal untuk handling input yang proper"""
    try:
        # Coba set terminal ke raw mode sebentar lalu reset
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            # Quick test dan reset
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    except:
        pass  # Skip jika tidak support

# Panggil di awal main
setup_terminal()

import readline  # Untuk line editing capabilities

def safe_input(prompt):
    """Input function dengan backspace support"""
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Input cancelled")
        sys.exit(1)

# Usage
password = safe_input("[?] Masukkan path dictionary: ")

class ShadowPasswordCracker:
    def __init__(self):
        self.start_time = None
        self.tested_count = 0
        self.found_password = None
        
    def print_banner(self):
        banner = """
    ██████╗ ██╗    ██╗    ██████╗██████╗  █████╗  ██████╗██╗  ██╗
    ██╔══██╗██║    ██║   ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
    ██████╔╝██║ █╗ ██║   ██║     ██████╔╝███████║██║     █████╔╝ 
    ██╔═══╝ ██║███╗██║   ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
    ██║     ╚███╔███╔╝   ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
    ╚═╝      ╚══╝╚══╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
    PASSWORD CRACKING ENGINE
        """
        print(banner)
        print(f"[+] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        
    def animate_loading(self, text, duration=2):
        """Loading animation"""
        animation = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        end_time = time.time() + duration
        i = 0
        
        while time.time() < end_time:
            print(f"\r[{animation[i % len(animation)]}] {text}", end="", flush=True)
            time.sleep(0.1)
            i += 1
        print("\r" + " " * 50 + "\r", end="", flush=True)
        
    def hash_pw(self, pw_str):
        """Compute MD5 digest (binary)"""
        pw_bytes = pw_str.encode('utf-8')
        m = hashlib.md5()
        m.update(pw_bytes)
        return m.digest()

    def xor_bytes(self, data: bytes, key: bytes) -> bytes:
        """XOR operation dengan key cycling"""
        if len(key) == 0:
            raise ValueError("Empty key")
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    def get_user_input(self):
        """Dapatkan input dari user dengan validasi"""
        print("\n[📁] FILE CONFIGURATION")
        print("-" * 30)
        
        while True:
            dict_path = input("[?] Masukkan path dictionary: ").strip()
            if os.path.exists(dict_path):
                break
            print("[!] File dictionary tidak ditemukan. Coba lagi.")
            
        while True:
            hash_bin = input("[?] Masukkan path hash file (.bin): ").strip()
            if os.path.exists(hash_bin):
                break
            print("[!] File hash tidak ditemukan. Coba lagi.")
            
        while True:
            enc_file = input("[?] Masukkan path encrypted file: ").strip()
            if os.path.exists(enc_file):
                break
            print("[!] File encrypted tidak ditemukan. Coba lagi.")
            
        return dict_path, hash_bin, enc_file

    def analyze_files(self, dict_path, hash_bin, enc_file):
        """Analisis file sebelum memulai cracking"""
        print("\n[🔍] FILE ANALYSIS")
        print("-" * 30)
        
        # Analisis dictionary
        try:
            with open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                dict_lines = sum(1 for _ in f)
            print(f"[+] Dictionary: {dict_lines} passwords")
        except:
            print("[!] Tidak bisa menganalisis dictionary")
            dict_lines = 0
            
        # Analisis hash file
        try:
            hash_size = os.path.getsize(hash_bin)
            print(f"[+] Hash file: {hash_size} bytes")
            if hash_size != 16:
                print(f"[!] Warning: MD5 hash biasanya 16 bytes, ini {hash_size} bytes")
        except:
            print("[!] Tidak bisa menganalisis hash file")
            
        # Analisis encrypted file
        try:
            enc_size = os.path.getsize(enc_file)
            print(f"[+] Encrypted file: {enc_size} bytes")
        except:
            print("[!] Tidak bisa menganalisis encrypted file")
            
        return dict_lines

    def crack_password(self, dict_path, hash_bin, enc_file):
        """Eksekusi password cracking"""
        print(f"\n[⚡] STARTING CRACKING PROCESS")
        print("-" * 35)
        
        # Load correct hash
        try:
            correct_pw_hash = open(hash_bin, "rb").read()
            print(f"[+] Loaded hash: {correct_pw_hash.hex()}")
        except Exception as e:
            print(f"[!] Error reading hash file: {e}")
            return False

        # Load encrypted file
        try:
            cipher = open(enc_file, "rb").read()
            print(f"[+] Loaded ciphertext: {len(cipher)} bytes")
        except Exception as e:
            print(f"[!] Error reading encrypted file: {e}")
            return False

        self.start_time = time.time()
        self.tested_count = 0
        last_update = time.time()
        
        print(f"\n[🔓] CRACKING IN PROGRESS...")
        print("─" * 40)

        try:
            with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    pw = line.strip()
                    if not pw:
                        continue
                        
                    self.tested_count += 1
                    
                    # Progress update setiap 1000 password atau 1 detik
                    current_time = time.time()
                    if self.tested_count % 1000 == 0 or current_time - last_update >= 1:
                        elapsed = current_time - self.start_time
                        speed = self.tested_count / elapsed if elapsed > 0 else 0
                        print(f"\r[⏱] Tested: {self.tested_count} | Speed: {speed:.1f} pwd/sec | Current: {pw:<20}", 
                              end="", flush=True)
                        last_update = current_time
                    
                    # Test password
                    user_pw_hash = self.hash_pw(pw)
                    if user_pw_hash == correct_pw_hash:
                        self.found_password = pw
                        return True
                        
        except KeyboardInterrupt:
            print(f"\n\n[!] Process interrupted by user")
            return False
        except Exception as e:
            print(f"\n\n[!] Error during cracking: {e}")
            return False
            
        return False

    def decrypt_file(self, enc_file, password):
        """Decrypt file menggunakan password yang ditemukan"""
        print(f"\n[🔓] DECRYPTING FILE...")
        print("-" * 25)
        
        try:
            cipher = open(enc_file, "rb").read()
            plain = self.xor_bytes(cipher, password.encode('utf-8'))
            
            print(f"[+] Successfully decrypted {len(cipher)} bytes")
            return plain
        except Exception as e:
            print(f"[!] Decryption failed: {e}")
            return None

    def display_results(self, plain_text, password, dict_path):
        """Tampilkan hasil dengan format yang menarik"""
        elapsed_time = time.time() - self.start_time
        
        print(f"\n{'🎌' * 25}")
        print("          MISSION ACCOMPLISHED!")
        print(f"{'🎌' * 25}")
        
        print(f"\n[📊] CRACKING STATISTICS:")
        print(f"    ├─ Passwords tested: {self.tested_count:,}")
        print(f"    ├─ Time elapsed: {elapsed_time:.2f} seconds")
        print(f"    ├─ Speed: {self.tested_count/elapsed_time:.1f} passwords/second")
        print(f"    └─ Dictionary: {os.path.basename(dict_path)}")
        
        print(f"\n[🔑] PASSWORD FOUND:")
        print(f"    └─ {password}")
        
        print(f"\n[📜] DECRYPTED CONTENT:")
        print("─" * 40)
        
        # Try different decodings
        decoded = False
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                text = plain_text.decode(encoding)
                print(f"Encoding: {encoding}")
                print("─" * 40)
                print(text)
                print("─" * 40)
                decoded = True
                break
            except UnicodeDecodeError:
                continue
                
        if not decoded:
            print("[!] Could not decode as text, showing hex dump:")
            print(plain_text.hex()[:200] + "..." if len(plain_text) > 200 else plain_text.hex())

    def main(self):
        """Main execution function"""
        self.print_banner()
        
        # Dapatkan input user
        dict_path, hash_bin, enc_file = self.get_user_input()
        
        # Analisis file
        total_passwords = self.analyze_files(dict_path, hash_bin, enc_file)
        
        # Konfirmasi mulai
        input(f"\n[🚀] Press Enter to start cracking {total_passwords:,} passwords...")
        
        # Loading animation
        self.animate_loading("Initializing cracking engine...")
        
        # Eksekusi cracking
        if self.crack_password(dict_path, hash_bin, enc_file):
            # Password ditemukan
            plain_text = self.decrypt_file(enc_file, self.found_password)
            if plain_text:
                self.display_results(plain_text, self.found_password, dict_path)
                
                # Tanya untuk save hasil
                save = input(f"\n[💾] Save decrypted content to file? (y/N): ").lower()
                if save == 'y':
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"decrypted_result_{timestamp}.txt"
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(f"Password: {self.found_password}\n")
                        f.write(f"Time: {datetime.now()}\n")
                        f.write(f"Passwords tested: {self.tested_count}\n")
                        f.write("\nDecrypted content:\n")
                        try:
                            f.write(plain_text.decode('utf-8'))
                        except:
                            f.write(plain_text.decode('latin-1', errors='replace'))
                    print(f"[+] Results saved to: {filename}")
        else:
            elapsed_time = time.time() - self.start_time
            print(f"\n\n{'💀' * 25}")
            print("        CRACKING FAILED!")
            print(f"{'💀' * 25}")
            print(f"\n[📊] Final Statistics:")
            print(f"    ├─ Passwords tested: {self.tested_count:,}")
            print(f"    ├─ Time elapsed: {elapsed_time:.2f} seconds")
            print(f"    └─ Coverage: {(self.tested_count/total_passwords)*100:.1f}% of dictionary")
            print(f"\n[❓] Suggestions:")
            print(f"    ├─ Try a different dictionary")
            print(f"    ├─ Verify hash file format")
            print(f"    └─ Check if password uses different encoding")

if __name__ == "__main__":
    try:
        cracker = ShadowPasswordCracker()
        cracker.main()
    except KeyboardInterrupt:
        print(f"\n\n[!] Program interrupted by user")
    except Exception as e:
        print(f"\n\n[💥] Critical error: {e}")