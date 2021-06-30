/**
 * Broken Data Encryption Standard (DES) implementation.
 *
 * From the author of grftool:
 * > GRAVITY's DES implementation is broken in that it uses
 * > a bitwise AND instead of a bitwise OR while creating the keyschedule
 * > causing the keyschedule to always be 0x80 bytes of 0.
 * Additionally only 1 round is being used when processing a 64 bit block.
 */
module zgrf.crypto.desbroken;

import std.bitmanip;

import zgrf.crypto.des;
import zgrf.bits;

/**
 * Encrypts data using the key 0x00. Key parameter is ignored.
 *
 * Params:
 *     data =  The data array to be encrypted
 *     key =   Ignored. Should be empty
 *
 * Returns: An array of bytes containing the encrypted data
*/
ubyte[] encrypt(const(ubyte)[] data, const(ubyte)[] key = []) pure
{
    return zgrf.crypto.des.encrypt2(data, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], &createSubkeys,
            &processBlock);
}

/**
 * Decrypts data using the key 0x00. Key parameter is ignored.
 *
 * Calls [zgrf.crypto.des.decrypt2] with the subkeys function [createSubkeys] and
 * the process function [processBlock].
 *
 * The data must be a multiple of 8 bytes long.
 *
 * Params:
 *     data =  The data array to be decrypted
 *     key =   Ignored. Should be empty
 *     unencryptedSize = The size/length of the unencrypted data.
 *                       The returning data will be truncated to this size if it has padding.
 *
 * Returns: An array of bytes containing the decrypted data
 */
ubyte[] decrypt(const(ubyte)[] data, const(ubyte)[] key, const size_t unencryptedSize) pure
in (data.length % 8 == 0, "Data must be a multiple of 64 bits (8 bytes)")
{
    return zgrf.crypto.des.decrypt2(data, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], unencryptedSize,
            &createSubkeys, &processBlock);
}

/**
 * Processes one block (8 bytes) of data.
 *
 * Unlike the original DES it only uses 1 round.
 *
 * Params:
 *  block = The block to process (must be 8 bytes long)
 *  subkeys = The subkeys to use for processing
 *
 * Returns:
 *  The processed block
 */
ubyte[] processBlock(const(ubyte)[] block, const BitArray[16] subkeys) pure
{
    return zgrf.crypto.des.processBlock(block, subkeys, 1);
}

/**
 * Creates 16 subkeys all of them being 0x00.
 *
 * They key parameter is unused.
 *
 * Params:
 *  key = Ignored. Should be empty
 *
 * Returns:
 *  16 BitArrays that contain the subkeys
 */
BitArray[16] createSubkeys(const(ubyte)[] key) pure
{
    const bool[48] bits = 0;
    BitArray[16] keys;
    foreach (i; 0 .. 16)
    {
        keys[i] = BitArray(bits);
    }

    return keys;
}

///
unittest
{
    const ubyte[] message = [0x48, 0x69, 0x67, 0x68, 0x20, 0x50, 0x72, 0x69, 0x65, 0x73, 0x74];
    const ubyte[] encodingKey = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const ubyte[] decodingKey = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    const ubyte[] encoded = [0x4D, 0x7D, 0x36, 0x69, 0x30, 0x11, 0x26, 0x7D,
        0x61, 0x77, 0x65, 0x54, 0x54, 0x05, 0x50, 0x11];

    const ubyte[] actualEncoded = encrypt(message, encodingKey);
    const ubyte[] actualDecoded = decrypt(encoded, decodingKey, message.length);

    assert(actualEncoded == encoded);
    assert(actualDecoded == message);
}
