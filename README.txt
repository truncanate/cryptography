Langkah menjalankan program:

1. Pastikan aplikasi python terinstall di computer
2. Instal library berikut:
	pip install pycryptodome (Untuk enkripsi dan dekripsi AES) --> pakai bersi 3.9.9
	pip install cryptography (Untuk operasi RSA (key generation, signing, verifying) --> pakai versi 3.4.7
	pip install PyQt5 (Untuk antarmuka grafis (GUI)) --> pakai versi 5.15.0
3. Setelah terinstall semua lakukan pemanggilan atau run program, apabila memanggil dengan terminal atau CLI maka lakukan pemanggilan sebagai berikut:
python C:/.../digisign_V3.4.py
di dua node/dua terminal/dua endpoint




Mode Enkripsi

-------------------------------------------------------------
Pilih Mode: Enkripsi

Generate RSA (atau Import Manual kunci RSA Anda)

Import Public Key Penerima (tujuan)

Masukkan Pesan (Plaintext)

Pilih Algoritma Hash: MD5 / SHA1 / SHA256 / SHA512

Klik “Process”

Output: Pesan terenkripsi dalam format Base64 siap dikirim

Mode Dekripsi
-------------------------------------------------------------
Pilih Mode: Dekripsi

Import Private Key Anda (Penerima)

Masukkan Ciphertext dari pengirim

Klik “Process”

Output:

Pesan asli

Validasi apakah pesan valid atau tidak (integritas dan autentikasi)