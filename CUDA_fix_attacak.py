import os
import binascii
import base58
import random
import pycuda.driver as cuda
import numpy as np
import hashlib
from pycuda.compiler import SourceModule
from ecdsa import SigningKey, SECP256k1
from functools import lru_cache
from queue import Queue
import threading
from concurrent.futures import ThreadPoolExecutor
import time

# Initialize CUDA and device context
cuda.init()
device = cuda.Device(0)
context = device.make_context()

# System configuration
num_threads = os.cpu_count()

# Queue to store matches
match_queue = Queue()

# Buffer to reduce disk writes (optimize I/O)
write_buffer_size = 10000

# Write the matches to a file in batches to minimize I/O bottleneck
def write_matches_to_file():
    buffer = []
    while True:
        match_data = match_queue.get()
        if match_data is None:
            break
        buffer.append(match_data)
        if len(buffer) >= write_buffer_size:
            with open("/mnt/c/Users/your_username/keyfound.txt", "a") as f:
                f.write('\n'.join(buffer))
            buffer = []
    if buffer:
        with open("/mnt/c/Users/your_username/keyfound.txt", "a") as f:
            f.write('\n'.join(buffer))
    match_queue.task_done()

# CUDA kernel for batch SHA-256
mod = SourceModule("""
    __device__ __constant__ unsigned int k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    __device__ unsigned int rotate_right(unsigned int x, unsigned int n) {
        return (x >> n) | (x << (32 - n));
    }

    __device__ void sha256_transform(const unsigned char *message, unsigned int *state) {
        unsigned int w[64];
        unsigned int a, b, c, d, e, f, g, h, i, t1, t2;

        for (i = 0; i < 16; i++) {
            w[i] = (message[i * 4] << 24) | (message[i * 4 + 1] << 16) | (message[i * 4 + 2] << 8) | (message[i * 4 + 3]);
        }

        for (i = 16; i < 64; i++) {
            unsigned int s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
            unsigned int s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        for (i = 0; i < 64; i++) {
            unsigned int s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            unsigned int ch = (e & f) ^ ((~e) & g);
            t1 = h + s1 + ch + k[i] + w[i];
            unsigned int s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
            t2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    __global__ void sha256_kernel_batch(const unsigned char *inputs, int input_size, unsigned int *output) {
        int idx = blockIdx.x * blockDim.x + threadIdx.x;

        if (idx < input_size) {
            unsigned int state[8] = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            };

            sha256_transform(&inputs[idx * 64], state);

            for (int i = 0; i < 8; i++) {
                output[idx * 8 + i] = state[i];
            }
        }
    }
""")

sha256_kernel_batch = mod.get_function("sha256_kernel_batch")

# GPU-based SHA-256 hashing with batching
def gpu_sha256_batch(input_data_batch):
    # Ensure all input strings have even length (needed for hex decoding)
    input_strs = [(data if isinstance(data, str) else data.decode('utf-8')) for data in input_data_batch]
    input_strs = [binascii.unhexlify(data if len(data) % 2 == 0 else '0' + data) for data in input_strs]
    
    output_strs = bytearray(32 * len(input_data_batch))

    input_gpu = cuda.mem_alloc(len(input_strs[0]) * len(input_data_batch))
    output_gpu = cuda.mem_alloc(len(output_strs))

    cuda.memcpy_htod(input_gpu, b''.join(input_strs))

    # input_size as numpy int32 for compatibility
    input_size = np.int32(len(input_data_batch))

    sha256_kernel_batch(input_gpu, input_size, output_gpu, block=(256, 1, 1), grid=(len(input_data_batch)//256+1, 1))

    cuda.memcpy_dtoh(output_strs, output_gpu)
    return [binascii.hexlify(output_strs[i * 32:(i + 1) * 32]).decode('utf-8') for i in range(len(input_data_batch))]

@lru_cache(maxsize=1024)
def private_key_to_compressed_public_key(private_key):
    sk = SigningKey.from_string(binascii.unhexlify(private_key), curve=SECP256k1)
    vk = sk.get_verifying_key()
    compressed_public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
    return compressed_public_key

def public_key_to_ripemd160(public_key):
    sha256_hash = gpu_sha256_batch([public_key])[0]
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(binascii.unhexlify(sha256_hash))
    return ripemd160.hexdigest()

# Convert public key to Bitcoin address
def public_key_to_p2pkh_address(public_key):
    ripemd160_hash = public_key_to_ripemd160(public_key)
    network_byte = '00'  # Main network for Bitcoin
    hashed_public_key_with_network_byte = network_byte + ripemd160_hash
    sha256_hash2 = gpu_sha256_batch([hashed_public_key_with_network_byte])[0]
    sha256_hash3 = gpu_sha256_batch([sha256_hash2])[0]
    checksum = sha256_hash3[:8]
    final_address_hex = hashed_public_key_with_network_byte + checksum
    return base58.b58encode(binascii.unhexlify(final_address_hex)).decode('utf-8'), ripemd160_hash

# Function to check keys
def check_key(private_key, prefix, suffix):
    private_key_hex = hex(private_key)[2:].zfill(64)
    compressed_public_key = private_key_to_compressed_public_key(private_key_hex)
    address, ripemd160_hash = public_key_to_p2pkh_address(compressed_public_key)

    if address.startswith(prefix) and address.endswith(suffix):
        match_data = f"Match found!\nPrivate Key: {private_key_hex}\nCompressed Public Key: {compressed_public_key}\nRIPEMD-160: {ripemd160_hash}\nAddress: {address}\n\n"
        match_queue.put(match_data)  # Queue the result to be written
        print(match_data)
        return True
    return False

# Generate random private key
def generate_random_private_key(start, end):
    return random.randint(start, end)

# Key scanning function
def scan_random_keys_in_range(start, end, prefix, suffix):
    context.push()
    count = 0
    start_time = time.time()

    try:
        while True:
            private_key = generate_random_private_key(start, end)
            check_key(private_key, prefix, suffix)
            count += 1

            if count % 10000 == 0:
                elapsed_time = time.time() - start_time
                rate = count / elapsed_time
                print(f"Saniyede taranan adres sayısı: {rate:.2f}")
    finally:
        context.pop()

# Multithreaded key scanning
def parallel_key_scanning_with_ranges(start, end, prefix, suffix):
    range_size = (end - start) // num_threads
    ranges = [(start + i * range_size, start + (i + 1) * range_size - 1) for i in range(num_threads)]

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(scan_random_keys_in_range, r[0], r[1], prefix, suffix) for r in ranges]
        for future in futures:
            future.result()

# Start the file writing thread
writer_thread = threading.Thread(target=write_matches_to_file)
writer_thread.start()

# Define the range of private keys to scan
start_range = 0x1  # Example start range
end_range = 0xFFFFFFFFFFFFFFFFF  # Example end range

# Define prefix and suffix for Bitcoin addresses
prefix = "13"  # Example prefix
suffix = "so"  # Example suffix

# Start the scanning process
parallel_key_scanning_with_ranges(start_range, end_range, prefix, suffix)

# Signal end of file writing and join threads
match_queue.put(None)
writer_thread.join()
