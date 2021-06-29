module zgrf.bits;

import std.bitmanip;

/**
 * Allocates a new [BitArray] of given count.
 *
 * Params:
 *  count = The amount of bits in the [BitArray]
 *
 * Returns:
 *  The new [BitArray]
 */
BitArray bitArrayOfSize(ulong count) pure
{
    bool[] buffer = new bool[count];
    return BitArray(buffer);
}

/**
 * Converts ubyte[] to [BitArray].
 *
 * Params:
 *  byteArr = The input ubyte[] to convert to a [BitArray]
 *
 * Returns:
 *  The converted [BitArray]
 *
 * See_Also:
 *  [toByteArray]
 */
BitArray toBitArray(const ubyte[] byteArr) pure
{
    auto bitArr = bitArrayOfSize(8 * byteArr.length);
    for (int i = 0; i < byteArr.length; ++i)
    {
        bitArr[8 * i + 0] = (byteArr[i] & 128) != 0;
        bitArr[8 * i + 1] = (byteArr[i] & 64) != 0;
        bitArr[8 * i + 2] = (byteArr[i] & 32) != 0;
        bitArr[8 * i + 3] = (byteArr[i] & 16) != 0;
        bitArr[8 * i + 4] = (byteArr[i] & 8) != 0;
        bitArr[8 * i + 5] = (byteArr[i] & 4) != 0;
        bitArr[8 * i + 6] = (byteArr[i] & 2) != 0;
        bitArr[8 * i + 7] = (byteArr[i] & 1) != 0;
    }
    return bitArr;
}

/**
 * Converts a [BitArray] to ubyte[].
 *
 * The input must be a multiple of 8 bytes. There is no bounds
 * check and no padding will be done.
 *
 * Params:
 *  bitArr = The [BitArray] to convert to ubyte[]
 *
 * Returns:
 *  Converted byte array
 *
 * See_Also:
 *  [toBitArray]
 */
ubyte[] toByteArray(const ref BitArray bitArr) pure
in (bitArr.length % 8 == 0, "Length of BitArray must be multiple of 8 bytes")
{
    const size_t length = bitArr.length / 8;
    ubyte[] arr = new ubyte[length];
    foreach (i; 0 .. length)
    {
        const j = i * 8;
        arr[i] = bitArr[j] << 7 |
            bitArr[j + 1] << 6 |
            bitArr[j + 2] << 5 |
            bitArr[j + 3] << 4 |
            bitArr[j + 4] << 3 |
            bitArr[j + 5] << 2 |
            bitArr[j + 6] << 1 |
            bitArr[j + 7];
    }

    return arr;
}

/**
 * Shifts the first length bits of the source [BitArray] by numBits
 * and stores it into the target [BitArray].
 *
 * Parameter length must be less than or equal to the source and target length.
 *
 * Params:
 *  source = Shift the bits given by this [BitArray]
 *  length = Defines how many bits to shift from the source. Cannot be higher than source/target length
 *  numBits = Defines the shift amount for each bit
 *  target = The output [BitArray] to store the shifted result to
 */
void shiftLeft(const ref BitArray source, size_t length, size_t numBits, ref BitArray target) pure
in (source.length >= length, "Source length is too short")
in (target.length >= length, "Target length is too short")
{
    for (size_t p = 0; p < length; ++p)
    {
        target[p] = source[(p + numBits) % length];
    }
}

/**
 * Swaps the nibbles of the input data.
 *
 * E.g. 0xABCDEF becomes 0xBADCFE
 *
 * Params:
 *  data = Input/Output that will be modified
 */
void swapNibbles(ref ubyte[] data) pure nothrow @safe @nogc
{
    foreach (i; 0 .. data.length)
    {
        data[i] = ((data[i] << 4) & 0xFF) | ((data[i] >> 4) & 0xFF);
    }
}
