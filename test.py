def translate(message):
    #string characters to unicode values
    charcodes = [ord(c) for c in message]
    #unicode values to 8-bit strings (removed binary indicator)
    bytes = []
    for char in charcodes:
        bytes.append(bin(char)[2:].zfill(8))
    #8-bit strings to list of bits as integers
    bits = []
    for byte in bytes:
        for bit in byte:
            bits.append(int(bit))
    return bits

def b2Tob16(value):
  #takes list of 32 bits
  #convert to string
  value = ''.join([str(x) for x in value])
  #creat 4 bit chunks, and add bin-indicator
  binaries = []
  for d in range(0, len(value), 4):
    binaries.append('0b' + value[d:d+4])
  #transform to hexadecimal and remove hex-indicator
  hexes = ''
  for b in binaries:
    hexes += hex(int(b ,2))[2:]
  return hexes

def fillZeros(bits, length=8, endian='LE'):
    if isinstance(bits, int):
        # Convert integer to list of bits
        bits = [int(bit) for bit in bin(bits)[2:].zfill(32)]

    l = len(bits)
    if endian == 'LE':
        for i in range(l, length):
            bits.append(0)
    else:
        while l < length:
            bits.insert(0, 0)
            l = len(bits)
    return bits

def chunker(bits, chunk_length=8):
    # divides list of bits into desired byte/word chunks,
    # starting at LSB
    chunked = []
    for b in range(0, len(bits), chunk_length):
        chunked.append(bits[b:b+chunk_length])
    return chunked

def initializer(values):
    #convert from hex to python binary string (with cut bin indicator ('0b'))
    binaries = [bin(int(v, 16))[2:] for v in values]
    #convert from python string representation to a list of 32 bit lists
    words = []
    for binary in binaries:
        word = []
        for b in binary:
            word.append(int(b))
        words.append(fillZeros(word, 32, 'BE'))
    return words

def preprocessMessage(message):
    # translate message into bits
    bits = translate(message)
    #message length
    length = len(bits)
    # get length in bits  of message (64 bit block)
    message_len = [int(b) for b in bin(length)[2:].zfill(64)]
    #if length smaller than 448 handle block individually otherwise
    #if exactly 448 then add single 1 and add up to 1024 and if longer than 448
    #create multiple of 512 - 64 bits for the length at the end of the message (big endian)
    if length < 448:
        #append single 1
        bits.append(1)
        #fill zeros little endian wise
        bits = fillZeros(bits, 448, 'LE')
        #add the 64 bits representing the length of the message
        bits = bits + message_len
        #return as list
        return [bits]
    elif 448 <= length <= 512:
        bits.append(1)
        #moves to next message block - total length = 1024
        bits = fillZeros(bits, 1024, 'LE')
        #replace the last 64 bits of the multiple of 512 with the original message length
        bits[-64:] = message_len
        #returns it in 512 bit chunks
        return chunker(bits, 512)
    else:
        bits.append(1)
        # loop until multiple of 512 + 64 bit message_len if message length exceeds 448 bits
        while (len(bits)+64) % 512 != 0:
            bits.append(0)
        #add the 64 bits representing the length of the message
        bits = bits + message_len
        #returns it in 512 bit chunks
        return chunker(bits, 512)

def chunkMessage(message, chunk_size=512):
    chunks = []
    for i in range(0, len(message), chunk_size):
        chunk = message[i:i+chunk_size]
        chunks.append(chunk)
    return chunks

def isTrue(x): return x == 1

#simple if
def if_(i, y, z): return y if isTrue(i) else z

#and - both arguments need to be true
def and_(i, j): return if_(i, j, 0)
def AND(i, j): return [and_(ia, ja) for ia, ja in zip(i,j)]

#simply negates argument
def not_(i): return if_(i, 0, 1)
def NOT(i): return [not_(x) for x in i]

#retrun true if either i or j is true but not both at the same time
def xor(i, j): return if_(i, not_(j), j)
def XOR(i, j): return [xor(ia, ja) for ia, ja in zip(i, j)]

#if number of truth values is odd then return true
def xorxor(i, j, l): return xor(i, xor(j, l))
def XORXOR(i, j, l): return [xorxor(ia, ja, la) for ia, ja, la, in zip(i, j, l)]

#get the majority of results, i.e., if 2 or more of three values are the same
def maj(i,j,k): return max([i,j,], key=[i,j,k].count)

# rotate right
def rotr(x, n):
    if isinstance(x, int):
        # Convert integer to list of bits
        x = [int(bit) for bit in bin(x)[2:].zfill(32)]
    
    if isinstance(x, list):
        return x[-n:] + x[:-n]
    else:
        raise TypeError("Input must be a list or integer for rotr function")



def shr(x, n):
    if isinstance(x, int):
        # Convert integer to list of bits
        x = [int(bit) for bit in bin(x)[2:].zfill(32)]

    if isinstance(x, list):
        return n * [0] + x[:-n]
    else:
        raise TypeError("Input must be a list or integer for shr function")

#full binary adder
def add(i, j):

    if isinstance(i, int):
        # Convert integer to list of bits
        i = [int(bit) for bit in bin(i)[2:].zfill(32)]

    length_i = len(i)

    if isinstance(j, int):
        # Convert integer to list of bits
        j = [int(bit) for bit in bin(j)[2:].zfill(32)]

    length_j = len(j)

    # Ensure lengths are the same
    if length_i != length_j:
        raise ValueError("Lengths of input lists must be the same")

    length = length_i
    sums = [0] * length  # Initialize the sums list with zeros

    # Check if the length is not zero to avoid division by zero
    if length == 0:
        return sums

    # Initialize carry
    c = 0

    # Iterate over indices
    for x in range(length-1, -1, -1):
        # Add the input bits with a double xor gate
        sums[x] = xorxor(i[x], j[x], c)
        # Carry over bit is equal to the most represented
        c = maj(i[x], j[x], c)

    return sums


def read_file(file_path):
    with open(file_path,'r') as file:
        return file.read()


def mine_block(file_contents, target_difficulty,digest):
    nonce = 0
    while True:
        combined_data = file_contents + str(nonce)#.encode('utf-8')
        hashed_data = digest
        
        if hashed_data.startswith('0' * target_difficulty):
            return nonce, hashed_data
        else:
            nonce += 1


print(translate('XO'))
print(b2Tob16([0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1]))

h = ['0x6a09e667', '0xbb67ae85', '0x3c6ef372', '0xa54ff53a', '0x510e527f', '0x9b05688c', '0x1f83d9ab', '0x5be0cd19']

k = ['0x428a2f98', '0x71374491', '0xb5c0fbcf', '0xe9b5dba5', '0x3956c25b', '0x59f111f1',
      '0x923f82a4','0xab1c5ed5', '0xd807aa98', '0x12835b01', '0x243185be', '0x550c7dc3',
      '0x72be5d74', '0x80deb1fe','0x9bdc06a7', '0xc19bf174', '0xe49b69c1', '0xefbe4786',
      '0x0fc19dc6', '0x240ca1cc', '0x2de92c6f','0x4a7484aa', '0x5cb0a9dc', '0x76f988da',
      '0x983e5152', '0xa831c66d', '0xb00327c8', '0xbf597fc7','0xc6e00bf3', '0xd5a79147',
      '0x06ca6351', '0x14292967', '0x27b70a85', '0x2e1b2138', '0x4d2c6dfc','0x53380d13',
      '0x650a7354', '0x766a0abb', '0x81c2c92e', '0x92722c85', '0xa2bfe8a1', '0xa81a664b',
      '0xc24b8b70', '0xc76c51a3', '0xd192e819', '0xd6990624', '0xf40e3585', '0x106aa070',
      '0x19a4c116','0x1e376c08', '0x2748774c', '0x34b0bcb5', '0x391c0cb3', '0x4ed8aa4a',
      '0x5b9cca4f', '0x682e6ff3','0x748f82ee', '0x78a5636f', '0x84c87814', '0x8cc70208',
      '0x90befffa', '0xa4506ceb', '0xbef9a3f7','0xc67178f2']

k_values = k
h_hex = h

# file_path = '/content/input.txt'
# file_contents = read_file(file_path)
# print(file_contents)

m = preprocessMessage("he")

print(m)
message = m

print(add([1,0,1], [1,1,1]))

#... list of constants need to be stored somewhere
#omitted here for reasons of space and presentation

#initialize mixin-constants
k = initializer(k)
#initialize initial hash values
h0, h1, h2, h3, h4, h5, h6, h7 = initializer(h)

#initialize values and constants
k = initializer(k_values)
h0, h1, h2, h3, h4, h5, h6, h7 = initializer(h_hex)
#message chunks
chunks = chunkMessage(message)
#main loop
for chunk in chunks:
    #message schedule
    #create lists of 32 bit words (512 bits / 32 = 16 words)
    w = chunker(chunk, 32)
    #extend length of chunk to 64 words, the remaining 48
    #initialized with zeros
    for _ in range(48):
        w.extend([0] * 32)
    
    print(type(w[1]))
    # Perform additions only if lengths are equal
    for i in range(16, 64):
        s0 = XORXOR(rotr(w[i-15], 7), rotr(w[i-15], 18), shr(w[i-15], 3))
        s1 = XORXOR(rotr(w[i-2], 17), rotr(w[i-2], 19), shr(w[i-2], 10))

          # Convert s0 and s1 to 32-bit words
        s0_word = fillZeros([s0], 32, 'BE')[0]
        s1_word = fillZeros([s1], 32, 'BE')[0]

        # Ensure all inputs have the same length
        length = 32  # or whatever the desired length is
        w_i_16 = fillZeros(w[i-16], length, 'BE')
        w_i_7 = fillZeros(w[i-7], length, 'BE')

        # Perform additions
        w[i] = add(add(add(w_i_16, s0_word), w_i_7), s1_word)


        # # # Check if lengths are equal before performing the addition
        # # if len(w[i-16]) == len(w[i-7]) == len(s0) == len(s1):
        # #     w[i] = add(add(add(w[i-16], s0), w[i-7]), s1)
        # else:
        #     raise ValueError("Lengths of input lists must be the same")


    # for i in range(16, 64):
    #       s0 = XORXOR(rotr(w[i-15], 7), rotr(w[i-15], 18), shr(w[i-15], 3) )
    #       s1 = XORXOR(rotr(w[i-2], 17), rotr(w[i-2], 19), shr(w[i-2], 10))
    #       w[i] = add(add(add(w[i-16], s0), w[i-7]), s1)

    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    f = h5
    g = h6
    h = h7

    for j in range(64):
        S1 = XORXOR(rotr(e, 6), rotr(e, 11), rotr(e, 25) )
        ch = XOR(AND(e, f), AND(NOT(e), g))
        temp1 = add(add(add(add(h, S1), ch), k[j]), w[j])
        S0 = XORXOR(rotr(a, 2), rotr(a, 13), rotr(a, 22))
        m = XORXOR(AND(a, b), AND(a, c), AND(b, c))
        temp2 = add(S0, m)
        h = g
        g = f
        f = e
        e = add(d, temp1)
        d = c
        c = b
        b = a
        a = add(temp1, temp2)

    #------------------------------------------------------------------------Done_--------------------------------------

    # for i in range(16, 64):
    #       s0 = XORXOR(rotr(w[i-15], 7), rotr(w[i-15], 18), shr(w[i-15], 3) ) 
    #       s1 = XORXOR(rotr(w[i-2], 17), rotr(w[i-2], 19), shr(w[i-2], 10))
    #       w[i] = add(add(add(w[i-16], s0), w[i-7]), s1)


    # a = h0
    # b = h1
    # c = h2
    # d = h3
    # e = h4
    # f = h5
    # g = h6
    # h = h7

    # for j in range(64):
    #       S1 = XORXOR(rotr(e, 6), rotr(e, 11), rotr(e, 25) )
    #       ch = XOR(AND(e, f), AND(NOT(e), g))
    #       temp1 = add(add(add(add(h, S1), ch), k[j]), w[j])
    #       S0 = XORXOR(rotr(a, 2), rotr(a, 13), rotr(a, 22))
    #       m = XORXOR(AND(a, b), AND(a, c), AND(b, c))
    #       temp2 = add(S0, m)
    #       h = g
    #       g = f
    #       f = e
    #       e = add(d, temp1)
    #       d = c
    #       c = b
    #       b = a
    #       a = add(temp1, temp2)


    h0 = add(h0, a)
    h1 = add(h1, b)
    h2 = add(h2, c)
    h3 = add(h3, d)
    h4 = add(h4, e)
    h5 = add(h5, f)
    h6 = add(h6, g)
    h7 = add(h7, h)

digest = ''
for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
    digest += b2Tob16(val)

print(digest)

target_difficulty = 1
nonce, mined_hash = mine_block('he', target_difficulty,digest)
print(digest)
print(nonce)
print(mined_hash)