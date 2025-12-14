# Implementasi-Enc-Dec-CBC

pip install pycryptodome

**Mengimpor Sub-Paket**

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

**Enkripsi**

def encrypt_aes_cbc(plaintext: str, key: bytes) -> str:
    """
    Enkripsi teks menggunakan AES-256-CBC.
    Mengembalikan string base64 yang sudah termasuk IV + ciphertext.
    """
    iv = get_random_bytes(AES.block_size)# IV 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv) # buat objek cipher AES dengan key,CBC dan iv(random)

    plaintext_bytes = plaintext.encode('utf-8')# Mengubah string plaintext mnjd bytes dgn mggunakan encoding UTF-8
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    # Gabungkan IV + ciphertext, lalu encode ke base64
    combined = iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')#mengubah data biner (iv + ciphertext) menjadi string Base64.

**Dekripsi**

def decrypt_aes_cbc(encrypted_b64: str, key: bytes) -> str: #dekripsi hasil enkripsi
    """
    Dekripsi string base64 (IV + ciphertext) menjadi teks asli.
    """
    combined = base64.b64decode(encrypted_b64)#ubah string base 64 mnj bytes
    iv = combined[:AES.block_size]#memisahkan IV dan ciphertext
    ciphertext = combined[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext_bytes = unpad(padded_plaintext, AES.block_size)

    return plaintext_bytes.decode('utf-8')

if __name__ == "__main__":
    print("=== Enkripsi & Dekripsi AES-256-CBC ===\n")
    key = get_random_bytes(32)
    print(f"Key (hex): {key.hex()}\n")
    print("Catatan: Simpan key ini dengan aman! Tanpa key yang sama, data tidak bisa didekripsi.\n")

    while True:
        print("Pilih menu:")
        print("1. Enkripsi teks baru")
        print("2. Dekripsi teks")
        print("3. Keluar")

        pilihan = input("\nMasukkan pilihan (1/2/3): ").strip()

        if pilihan == "1":
            teks = input("\nMasukkan teks yang ingin dienkripsi: ").strip()
            if teks:
                encrypted = encrypt_aes_cbc(teks, key)
                print("\nHasil Enkripsi (Base64):")
                print(encrypted)
                print("(Simpan teks ini untuk didekripsi nanti)\n")
            else:
                print("Teks tidak boleh kosong!\n")

        elif pilihan == "2":
            encrypted_input = input("\nMasukkan teks terenkripsi (Base64): ").strip()
            if encrypted_input:
                try:
                    decrypted = decrypt_aes_cbc(encrypted_input, key)
                    print("\nHasil Dekripsi:")
                    print(decrypted + "\n")
                except Exception as e:
                    print(f"Gagal dekripsi! Pastikan input valid dan menggunakan key yang sama.\nError: {e}\n")
            else:
                print("Input tidak boleh kosong!\n")

        elif pilihan == "3":
            print("Terima kasih! Program selesai.")
            break

        else:
            print("Pilihan tidak valid. Silakan coba lagi.\n")
