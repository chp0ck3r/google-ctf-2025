# NUMEROLOGY (solved by: @MrSpavn)

## Category: Crypto • Points: 50


## Description:
### *I made a new cipher, can you help me test it? I'll give you the key, please use it to decrypt my ciphertext.*
---
## Challenge Overview

We're given a modified version of the ChaCha cipher with several critical weaknesses:
- Only 1 round of mixing (instead of the standard 20 rounds)
- Known key structure with predictable zero words
- Known plaintext-ciphertext pairs for learning
- Need to recover a secret counter and decrypt the flag

## Key Observations

1. **Reduced Rounds**: With only 1 round, the cipher becomes vulnerable to linear cryptanalysis.

2. **Structured Key**: The key has a specific pattern with known zero positions:
   ```
   Key words: [0, k1, 0, k3, k4, 0, k6, 0]
   ```

3. **Predictable Keystream**: Due to the structure and single round, certain keystream words can be computed directly from the key:
   - `ks[5] = 2*k1`
   - `ks[7] = 2*k3`
   - `ks[10] = 2*k6`

## Attack Strategy

1. **Extract Known Key Material**:
   - From the challenge package, we get the known key hex
   - Parse it to get k1, k3, k4, k6

2. **Bruteforce the Counter**:
   - The counter is 32-bit (4 billion possibilities)
   - For each candidate counter:
     - Initialize the ChaCha state
     - Perform 1 round of mixing
     - Compute the keystream
     - Use known keystream words to verify correctness

3. **Flag Decryption**:
   - Once the correct counter is found:
     - Generate the full keystream
     - XOR with the ciphertext to get plaintext
## Solution Code
```python
import json
import struct
from itertools import product
from tqdm import tqdm

def bytes_to_words(b):
    return list(struct.unpack('<' + 'I' * (len(b) // 4), b))

def words_to_bytes(w):
    return struct.pack('<' + 'I' * len(w), *w)

def rotl32(v, c):
    v &= 0xFFFFFFFF
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF

def mix_bits(state_list, a_idx, b_idx, c_idx, d_idx):
    a, b, c, d = (state_list[a_idx], state_list[b_idx], state_list[c_idx], state_list[d_idx])
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = rotl32(d, 8)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = rotl32(b, 7)
    state_list[a_idx], state_list[b_idx], state_list[c_idx], state_list[d_idx] = a, b, c, d

def make_block(key_bytes, nonce_bytes, counter_int, rounds_to_execute=1):
    state = [0] * 16
    state[4:12] = bytes_to_words(key_bytes)
    state[12] = counter_int & 0xFFFFFFFF
    state[13:16] = bytes_to_words(nonce_bytes)
    initial_state = state.copy()
    
    mix_bits(state, 0, 4, 8, 12)
    
    for i in range(16):
        state[i] = (state[i] + initial_state[i]) & 0xFFFFFFFF
    return words_to_bytes(state)

def decrypt_flag(package_path):
    with open(package_path) as f:
        package = json.load(f)
    
    key_hex = package['cipher_parameters']['key']
    flag_cipher_hex = package['flag_ciphertext']
    key_bytes = bytes.fromhex(key_hex)
    flag_cipher = bytes.fromhex(flag_cipher_hex)
    
    key_words = bytes_to_words(key_bytes)
    k1, k3, k4, k6 = key_words[1], key_words[3], key_words[4], key_words[6]
    known_ks_parts = {
        5: (2 * k1) & 0xFFFFFFFF,
        7: (2 * k3) & 0xFFFFFFFF,
        10: (2 * k6) & 0xFFFFFFFF
    }
    
    cipher_words = bytes_to_words(flag_cipher.ljust(64, b'\0')[:64])
    target_prefix = b"CTF{"
    
    for counter in tqdm(range(0, 2**32), desc="Bruteforcing counter"):
        state = [0]*16
        state[4:12] = [0, k1, 0, k3, k4, 0, k6, 0]
        state[12] = counter
        state[13:16] = [0, 0, 0]
        initial_state = state.copy()
        
        mix_bits(state, 0, 4, 8, 12)
        
        ks_words = [ (state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16) ]
        for idx, val in known_ks_parts.items():
            ks_words[idx] = val
        
        valid = True
        decrypted = bytearray()
        for i in range(min(12, len(cipher_words))):
            p = cipher_words[i] ^ ks_words[i]
            decrypted.extend(p.to_bytes(4, 'little'))
            if i < 2 and len(decrypted) >= len(target_prefix):
                if decrypted[:len(target_prefix)] != target_prefix:
                    valid = False
                    break
        
        if valid and decrypted.startswith(target_prefix):
            flag = decrypted.decode('utf-8', errors='ignore').split('\0')[0]
            if '}' in flag:
                print(f"Found counter: {counter}")
                print(f"Decrypted flag: {flag}")
                return
    
    print("Flag not found. Try expanding the search.")

if __name__ == '__main__':
    decrypt_flag("ctf_challenge_package.json")
```
## Results

1. Run the script:
   ```bash
   python solve.py
   ```

2. output:
   ``` 
   Bruteforcing counter:   0%
   Found counter: 32279
   Decrypted flag: CTF{w3_aRe_g0Nn@_ge7_MY_FuncKee_monkey_!!}
    ```
