/**
 * Implements the Data Encryption Standard (DES).
 */
module zgrf.crypto.des;

import std.bitmanip;

import zgrf.bits;

// Permuted choice 1
immutable ubyte[] pc1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
];

// Permuted choice 2
immutable ubyte[] pc2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
];

// Initial permutation
immutable ubyte[] ip = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
];

// Expansion table (Bit-Selection table)
immutable ubyte[] e = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
];

// Substition Boxes
immutable ubyte[][] sboxes = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    ]
];

// Permutation
immutable ubyte[] p = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
];

// Final Permutation
immutable ubyte[] fp = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
];

// Shift table
immutable ubyte[] shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/**
 * Pointer to a routine that generates the subkeys.
 * The mixcrypt algorithm for example uses a custom routine.
 */
alias CreateSubkeysFunc = BitArray[16]function(const(ubyte)[] key) pure;
/**
 * Pointer to a routine that processes one block (8 byte).
 * The mixcrypt algorithm for example uses a custom routine.
 */
alias ProcessBlockFunc = ubyte[]function(const(ubyte)[] block, const BitArray[16] subkeys) pure;

/**
 * Encrypts data using a specific key.
 *
 * The input key must be exactly 8 bytes long.
 *
 * Params:
 *  data = The data array to be encrypted
 *  key = The key used to encrypt the data
 *  ksFunc = The function responsible for creating the subkeys
 *  processFunc = The function responsible for processing one block of data
 *
 * Returns:
 *  An array of bytes containing the encrypted data
 *
 * See_Also:
 *  [encrypt]
*/
ubyte[] encrypt2(const(ubyte)[] data, const(ubyte)[] key, CreateSubkeysFunc ksFunc, ProcessBlockFunc processFunc) pure
in (key.length == 8, "Key must be 64 bits (8 bytes) long")
{

    size_t length = data.length;
    const ubyte extraLength = length % 8;
    const size_t paddedLength = (extraLength > 0) ? length + 8 - extraLength : length;
    length -= extraLength;

    auto subkeys = ksFunc(key);

    ubyte[] encryptedData = new ubyte[paddedLength];

    for (auto i = 0; i < length; i += 8)
    {
        const processedBlock = processFunc(data[i .. i + 8], subkeys);
        encryptedData[i .. i + 8] = processedBlock;
    }

    if (extraLength > 0)
    {
        const ubyte padding = 8 - extraLength;
        ubyte[] lastBlock = new ubyte[8];
        lastBlock[0 .. extraLength] = data[length .. length + extraLength];
        foreach (i; 0 .. padding)
        {
            lastBlock[extraLength + i] = padding;
        }
        const processedBlock = processFunc(lastBlock, subkeys);
        encryptedData[length .. length + 8] = processedBlock;
    }

    return encryptedData;
}

/**
 * Encrypts data using a specific key.
 *
 * The input key must be exactly 8 bytes long.
 *
 * Params:
 *  data = The data array to be encrypted
 *  key = The key used to encrypt the data
 *
 * Returns:
 *  An array of bytes containing the encrypted data
 *
 * See_Also:
 *  [encrypt2]
 */
ubyte[] encrypt(const(ubyte)[] data, const(ubyte)[] key) pure
{
    return encrypt2(data, key, &createSubkeys, &processBlock);
}

/**
 * Decrypts data using a specific key.
 *
 * The input data must be a multiple of 8 bytes and the input key
 * must be exactly 8 bytes long.
 *
 * Params:
 *  data = The data array to be decrypted
 *  key =  The key used to decrypt the data
 *  unencryptedSize = The size/length of the unencrypted data.
 *                    The returning data will be truncated to this size if it has padding.
 *  ksFunc = The function responsible for creating the subkeys
 *  processFunc = The function responsible for processing one block of data
 *
 * Returns: An array of bytes containing the decrypted data
 *
 * See_Also:
 *  [decrypt]
*/
ubyte[] decrypt2(const(ubyte)[] data, const(ubyte)[] key, const size_t unencryptedSize, CreateSubkeysFunc ksFunc,
        ProcessBlockFunc processFunc) pure
in (data.length % 8 == 0, "Data must be a multiple of 64 bits (8 bytes)")
in (key.length == 8, "Key must be 64 bits (8 bytes) long")
{

    const size_t length = data.length;

    auto subkeys = ksFunc(key);
    BitArray temp;
    foreach (i; 0 .. 8)
    {
        temp = subkeys[i];
        subkeys[i] = subkeys[15 - i];
        subkeys[15 - i] = temp;
    }

    ubyte[] decryptedData = new ubyte[length];

    for (auto i = 0; i < length; i += 8)
    {
        const processedBlock = processFunc(data[i .. i + 8], subkeys);
        decryptedData[i .. i + 8] = processedBlock;
    }

    const long padding = decryptedData.length - unencryptedSize;

    if (padding > 0)
    {
        return decryptedData[0 .. $ - padding];
    }
    else
    {
        return decryptedData;
    }
}

/**
 * Decrypts data using a specific key.
 *
 * Calls [decrypt2] with the subkeys function [createSubkeys] and
 * the process function [processBlock].
 *
 * The input data must be a multiple of 8 bytes and the input key
 * must be exactly 8 bytes long.
 *
 * Params:
 *  data = The data array to be decrypted
 *  key =  The key used to decrypt the data
 *  unencryptedSize = The size/length of the unencrypted data.
 *                    The returning data will be truncated to this size if it has padding.
 *
 * Returns: An array of bytes containing the decrypted data
 *
 * See_Also:
 *  [decrypt2]
*/
ubyte[] decrypt(const(ubyte)[] data, const(ubyte)[] key, const size_t unencryptedSize) pure
{
    return decrypt2(data, key, unencryptedSize, &createSubkeys, &processBlock);
}

/**
 * Processes one block (8 bytes) of data.
 *
 * The rounds must be greater than 0 and equal or smaller than 16.
 *
 * Params:
 *  block = The block to process (must be 8 bytes long)
 *  subkeys = The subkeys to use for processing
 *  rounds = The number of rounds applied
 *
 * Returns:
 *  The processed block
 *
 */
ubyte[] processBlock(const(ubyte)[] block, const BitArray[16] subkeys, const int rounds) pure
in (rounds > 0 && rounds <= 16, "Rounds must be greater than 0 and equal or smaller than 16")
{
    auto blockBits = toBitArray(block);

    auto blockAfterIP = bitArrayOfSize(64);
    foreach (i; 0 .. 64)
    {
        blockAfterIP[i] = blockBits[ip[i] - 1];
    }

    BitArray[] leftBlock;
    BitArray[] rightBlock;

    const size_t reservedLeftBlockSize = leftBlock.reserve(rounds + 1);
    const size_t reservedRightBlockSize = rightBlock.reserve(rounds + 1);
    assert(reservedLeftBlockSize >= rounds + 1);
    assert(reservedLeftBlockSize == leftBlock.capacity);
    assert(reservedRightBlockSize >= rounds + 1);
    assert(reservedRightBlockSize == rightBlock.capacity);

    foreach (i; 0 .. rounds + 1)
    {
        leftBlock ~= bitArrayOfSize(32);
        rightBlock ~= bitArrayOfSize(32);
    }

    foreach (i; 0 .. 32)
    {
        leftBlock[0][i] = blockAfterIP[i];
        rightBlock[0][i] = blockAfterIP[i + 32];
    }

    foreach (i; 1 .. rounds + 1)
    {
        leftBlock[i] = rightBlock[i - 1];
        rightBlock[i] = leftBlock[i - 1] ^ feistel(rightBlock[i - 1], subkeys[i - 1]);
    }

    auto concatenatedBlocks = bitArrayOfSize(64);
    foreach (i; 0 .. 32)
    {
        concatenatedBlocks[i] = rightBlock[rounds][i];
        concatenatedBlocks[i + 32] = leftBlock[rounds][i];
    }

    auto finalBlock = bitArrayOfSize(64);
    foreach (i; 0 .. 64)
    {
        finalBlock[i] = concatenatedBlocks[fp[i] - 1];
    }

    return toByteArray(finalBlock);
}

/**
 * ditto, except that rounds is fixed at 16.
 */
ubyte[] processBlock(const(ubyte)[] block, const BitArray[16] subkeys) pure
{
    return processBlock(block, subkeys, 16);
}

/**
 * Creates 16 subkeys given the de-/encryption key.
 *
 * Params:
 *  key = The de-/encryption key
 *
 * Returns:
 *  16 BitArrays that contain the subkeys
 */
BitArray[16] createSubkeys(const(ubyte)[] key) pure
{
    auto keyBits = toBitArray(key);
    auto keyAfterPC1 = bitArrayOfSize(56);

    foreach (i; 0 .. 56)
    {
        keyAfterPC1[i] = keyBits[pc1[i] - 1];
    }

    BitArray[17] leftKey;
    BitArray[17] rightKey;

    foreach (i; 0 .. 17)
    {
        leftKey[i] = bitArrayOfSize(56);
        rightKey[i] = bitArrayOfSize(28);
    }

    foreach (i; 0 .. 28)
    {
        leftKey[0][i] = keyAfterPC1[i];
        rightKey[0][i] = keyAfterPC1[i + 28];
    }

    foreach (i; 1 .. 17)
    {
        shiftLeft(leftKey[i - 1], 28, shifts[i - 1], leftKey[i]);
        shiftLeft(rightKey[i - 1], 28, shifts[i - 1], rightKey[i]);
    }

    BitArray[16] keysAfterPC2;

    foreach (i; 1 .. 17)
    {
        foreach (p; 0 .. 28)
        {
            leftKey[i][p + 28] = rightKey[i][p];
        }

        keysAfterPC2[i - 1] = bitArrayOfSize(48);

        foreach (q; 0 .. 48)
        {
            keysAfterPC2[i - 1][q] = leftKey[i][pc2[q] - 1];
        }
    }

    return keysAfterPC2;
}

/**
 * Apply the feistel routine to a given block of data.
 * Used by [processBlock].
 *
 * Params:
 *  block = The block to apply the routine to
 *  subkey = The subkey to use for this process
 *
 * Returns:
 *  The processed block
 */
BitArray feistel(const ref BitArray block, const ref BitArray subkey) pure
{
    auto expandedBlock = bitArrayOfSize(48);

    foreach (i; 0 .. 48)
    {
        expandedBlock[i] = block[e[i] - 1];
    }

    expandedBlock ^= subkey;

    auto substitutedBlock = bitArrayOfSize(32);
    foreach (i; 0 .. 8)
    {
        const j = i * 6;
        const row = expandedBlock[j] * 2 + expandedBlock[j + 5] * 1;
        const col = expandedBlock[j + 1] * 8 +
            expandedBlock[j + 2] * 4 +
            expandedBlock[j + 3] * 2 +
            expandedBlock[j + 4] * 1;

        const nibble = sboxes[i][row * 16 + col];
        const k = j - i * 2;
        substitutedBlock[k] = (nibble & 8) >> 3;
        substitutedBlock[k + 1] = (nibble & 4) >> 2;
        substitutedBlock[k + 2] = (nibble & 2) >> 1;
        substitutedBlock[k + 3] = (nibble & 1);
    }

    auto sBlockAfterP = bitArrayOfSize(32);
    foreach (i; 0 .. 32)
    {
        sBlockAfterP[i] = substitutedBlock[p[i] - 1];
    }

    return sBlockAfterP;
}

///
unittest
{
    const ubyte[] message = [0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x0A, 0x0B];
    const ubyte[] key = [0x0e, 0x32, 0x92, 0x32, 0xea, 0x6d, 0x0d, 0x73];
    const ubyte[] encoded = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xAF, 0x73, 0x75, 0x18, 0xB3, 0xB4, 0xD2, 0x9D];

    const ubyte[] actualEncoded = encrypt(message, key);
    const ubyte[] actualDecoded = decrypt(encoded, key, message.length);

    assert(actualEncoded == encoded);
    assert(actualDecoded == message);
}
