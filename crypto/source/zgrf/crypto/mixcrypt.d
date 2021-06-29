/**
 * Provides de-/encryption methods for Gravity's Mixcrypt
 * algorithm.
 * It uses a combination of a custom routine and their
 * broken DES.
 */
module zgrf.crypto.mixcrypt;

import std.bitmanip;

import zgrf.crypto.desbroken;
import zgrf.bits;

/**
 * Encrypts data using the key 0x00. Key parameter is ignored.
 *
 * Params:
 *     data = The data array to be encrypted
 *     key = Ignored. Should be empty
 *
 * Returns: An array of bytes containing the encrypted data
 */
ubyte[] encrypt(const(ubyte)[] data, const(ubyte)[] key = []) pure
{
    size_t length = data.length;
    const ubyte extraLength = length % 8;
    const size_t paddedLength = (extraLength > 0) ? length + 8 - extraLength : length;
    length -= extraLength;

    auto subkeys = createSubkeys(key);

    const auto cycle = getCycle(length);

    ubyte[] encryptedData = new ubyte[paddedLength];

    auto j = 0;
    for (auto i = 0, step = 0; i < length; i += 8)
    {
        step = i / 8;
        if (step < 20 || step % cycle == 0)
        {
            const processedBlock = processBlock(data[i .. i + 8], subkeys);
            encryptedData[i .. i + 8] = processedBlock;
        }
        else
        {
            if (j == 7)
            {
                const permBlock = permutateByteBlock(data[i .. i + 8], false);
                encryptedData[i .. i + 8] = permBlock;
                j = 0;
            }
            else
            {
                encryptedData[i .. i + 8] = data[i .. i + 8];
            }
            j++;
        }
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
        const auto step = length / 8;
        if (step < 20 || step % cycle == 0)
        {
            const processedBlock = processBlock(lastBlock, subkeys);
            encryptedData[length .. length + 8] = processedBlock;
        }
        else
        {
            if (j == 7)
            {
                const permBlock = permutateByteBlock(lastBlock, false);
                encryptedData[length .. length + 8] = permBlock;
            }
            else
            {
                encryptedData[length .. length + 8] = lastBlock;
            }
        }
    }

    return encryptedData;
}

/**
 * Decrypts data using the key 0x00. Key parameter is ignored.
 *
 * The input data must be a multiple of 8 bytes long and the
 * unencryptedSize cannot be larger than the encrypted size.
 *
 * Params:
 *  data = The data array to be decrypted
 *  key = Ignored. Should be empty
 *  unencryptedSize = The size/length of the unencrypted data.
 *                    The returning data will be truncated to this size if it has padding.
 *
 * Returns: An array of bytes containing the decrypted data
 */
ubyte[] decrypt(const(ubyte)[] data, const(ubyte)[] key, const size_t unencryptedSize) pure
in (data.length % 8 == 0, "Data must be a multiple of 64 bits (8 bytes)")
in (unencryptedSize <= data.length, "Unencrypted data size cannot be bigger than encrypted data size")
{
    const size_t length = data.length;

    auto subkeys = createSubkeys(key);

    const auto cycle = getCycle(unencryptedSize);

    ubyte[] decryptedData = new ubyte[length];

    for (auto i = 0, j = 0, step = 0; i < length; i += 8)
    {
        step = i / 8;
        if (step < 20 || step % cycle == 0)
        {
            const processedBlock = processBlock(data[i .. i + 8], subkeys);
            decryptedData[i .. i + 8] = processedBlock;
        }
        else
        {
            if (j == 7)
            {
                const permBlock = permutateByteBlock(data[i .. i + 8]);
                decryptedData[i .. i + 8] = permBlock;
                j = 0;
            }
            else
            {
                decryptedData[i .. i + 8] = data[i .. i + 8];
            }
            j++;
        }
    }

    const size_t padding = decryptedData.length - unencryptedSize;
    return decryptedData[0 .. $ - padding];
}

private int getCycle(const size_t unencryptedSize) pure
{
    ubyte digits = 0;
    size_t step = unencryptedSize;
    while (step > 0)
    {
        step /= 10;
        digits++;
    }
    if (digits == 0)
    {
        digits = 1;
    }

    int cycle;
    if (digits < 3)
    {
        cycle = 1;
    }
    else if (digits < 5)
    {
        cycle = digits + 1;
    }
    else if (digits < 7)
    {
        cycle = digits + 9;
    }
    else
    {
        cycle = digits + 15;
    }

    return cycle;
}

private ubyte substituteLastByte(const ubyte lastByte) pure
{
    ubyte result;
    switch (lastByte)
    {
    case 0x77:
        result = 0x48;
        break;
    case 0x48:
        result = 0x77;
        break;
    case 0x00:
        result = 0x2B;
        break;
    case 0x2B:
        result = 0x00;
        break;
    case 0x01:
        result = 0x68;
        break;
    case 0x68:
        result = 0x01;
        break;
    case 0x60:
        result = 0xFF;
        break;
    case 0xFF:
        result = 0x60;
        break;
    case 0x6C:
        result = 0x80;
        break;
    case 0x80:
        result = 0x6C;
        break;
    case 0xB9:
        result = 0xC0;
        break;
    case 0xC0:
        result = 0xB9;
        break;
    case 0xEB:
        result = 0xFE;
        break;
    case 0xFE:
        result = 0xEB;
        break;
    default:
        result = lastByte;
        break;
    }
    return result;
}

private ubyte[8] permutateByteBlock(const ubyte[] data, bool isDecryption = true) pure
{
    ubyte[8] block;
    if (isDecryption)
    {
        block[0] = data[3];
        block[1] = data[4];
        block[2] = data[6];
        block[3] = data[0];
        block[4] = data[1];
        block[5] = data[2];
        block[6] = data[5];
    }
    else
    {
        block[0] = data[3];
        block[1] = data[4];
        block[2] = data[5];
        block[3] = data[0];
        block[4] = data[1];
        block[5] = data[6];
        block[6] = data[2];
    }

    const ubyte lastByte = substituteLastByte(data[7]);
    block[7] = lastByte;

    return block;
}

///
unittest
{
    const ubyte[] key = [0x0e, 0x32, 0x92, 0x32, 0xea, 0x6d, 0x0d, 0x73];
    const ubyte[] message = [0x64, 0x61, 0x74, 0x61, 0x5C, 0x61, 0x6C, 0x64, 0x65,
        0x5F, 0x61, 0x6C, 0x63, 0x68, 0x65, 0x2E, 0x67, 0x61,
        0x74, 0x00, 0x00, 0x00, 0x00, 0x00];
    const ubyte[] encoded = [0x30, 0x65, 0x25, 0x25, 0x08, 0x24, 0x39, 0x30, 0x64,
        0x5B, 0x21, 0x6D, 0x37, 0x6D, 0x31, 0x7A, 0x63, 0x71,
        0x65, 0x11, 0x51, 0x00, 0x55, 0x04];

    const ubyte[] actualDecoded = decrypt(encoded, key, 24);
    const ubyte[] actualEncoded = encrypt(message, key);

    assert(actualEncoded == encoded);
    assert(actualDecoded == message);
}

