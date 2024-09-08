import os
import binascii
import hashlib
import random
from ecdsa import SigningKey, SECP256k1
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from pybloom_live import BloomFilter
import threading

# Sistem yapılandırması
num_threads = os.cpu_count()

# Bloom filter oluştur
bloom = BloomFilter(capacity=1000000, error_rate=0.001)

# Hedef hash'leri bloom filter'a ekleyelim
target_prefix = "20"
target_suffix = "a5"

# Kuyruktan anahtarları dosyaya yazan bir fonksiyon
match_queue = Queue()
write_buffer_size = 10000  # Buffer boyutu

def write_matches_to_file():
    buffer = []
    while True:
        match_data = match_queue.get()
        if match_data is None:
            break
        buffer.append(match_data)
        if len(buffer) >= write_buffer_size:
            with open("keyfound.txt", "a") as f:
                f.write('\n'.join(buffer) + '\n')
            buffer = []
    if buffer:
        with open("keyfound.txt", "a") as f:
            f.write('\n'.join(buffer) + '\n')
    match_queue.task_done()

# Compressed public key üretme
def private_key_to_compressed_public_key(private_key):
    sk = SigningKey.from_string(binascii.unhexlify(private_key), curve=SECP256k1)
    vk = sk.get_verifying_key()
    compressed_public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
    return compressed_public_key

# RIPEMD-160 hash hesaplama
def public_key_to_ripemd160(public_key):
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    return ripemd160.hexdigest()

# Tarama ve hash kontrol fonksiyonu
def check_key(private_key):
    private_key_hex = hex(private_key)[2:].zfill(64)
    compressed_public_key = private_key_to_compressed_public_key(private_key_hex)
    ripemd160_hash = public_key_to_ripemd160(compressed_public_key)
    
    # Bloom filter kullanarak hash'i ön filtreye sokalım
    if ripemd160_hash.startswith(target_prefix) and ripemd160_hash.endswith(target_suffix):
        if ripemd160_hash not in bloom:
            print(f"Match found!\nPrivate Key: {private_key_hex}\nRIPEMD-160: {ripemd160_hash}")
            bloom.add(ripemd160_hash)
            match_queue.put(f"Match found!\nPrivate Key: {private_key_hex}\nRIPEMD-160: {ripemd160_hash}")
    return False

# Tarama işlemi (örnek bir aralık)
def scan_random_keys_in_range(start, end):
    for private_key in range(start, end):
        check_key(private_key)

# Paralel tarama
def parallel_key_scanning_with_ranges(start, end):
    range_size = (end - start) // num_threads
    ranges = [(start + i * range_size, start + (i + 1) * range_size - 1) for i in range(num_threads)]

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(scan_random_keys_in_range, r[0], r[1]) for r in ranges]
        for future in futures:
            future.result()

# Dosyaya yazma thread'ini başlat
writer_thread = threading.Thread(target=write_matches_to_file)
writer_thread.start()

# Private key aralığı
start_range = 0x1
end_range = 0xffffffffffffffff

# Tarama işlemini başlat
parallel_key_scanning_with_ranges(start_range, end_range)

# Dosya yazma işlemini durdur
match_queue.put(None)
writer_thread.join()
