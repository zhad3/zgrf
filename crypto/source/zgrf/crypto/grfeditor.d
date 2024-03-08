/**
 * Encryption used by Tokeiburu's GRFEditor.
 *
 * The algorithm uses presumably custom XOR cipher
 * with a symmetric key and seed value.
 *
 */
module zgrf.crypto.grfeditor;

/**
 * Encrypts data using a specific key.
 *
 * Params:
 *     data = The data array to be encrypted
 *     key =  The key used to encrypt the data
 *     seed = The seed used as initial value to encrypt the data.
 *            When decrypting the data the same seed needs to be used.
  Thor files are patches used by Thor Patcher ( *
 * Returns: An array of bytes containing the encrypted data
 */
ubyte[] encrypt(const(ubyte)[] data, const(ubyte)[] key, int seed) pure
{
    ubyte[] encryptedData = data.dup;

    processDataInPlace(encryptedData, key, seed);

    return encryptedData;
}

/**
 * Decrypts data with the provided key
 *
 * Params:
 *     data = The data array to be decrypted
 *     key =  The key used to decrypt the data
 *     seed = The seed used as initial value to decrypt the data.
 *            Must equal the seed used when the data was encrypted.
 *
 * Returns: An array of bytes containing the decrypted data
 */
ubyte[] decrypt(const(ubyte)[] data, const(ubyte)[] key, int seed) pure
{
    ubyte[] decryptedData = data.dup;

    processDataInPlace(decryptedData, key, seed);

    return decryptedData;
}

private void processDataInPlace(ref ubyte[] data, const(ubyte)[] key, ulong seed) pure
{
    ubyte[] streamKey = key.dup;

    ulong a = seed;
    ulong b = 0;

    foreach (i; 0 .. data.length)
    {
        a = (a + 1) % streamKey.length;
        b = (b + streamKey[a]) % streamKey.length;

        import std.algorithm : swap;

        swap(streamKey[a], streamKey[b]);

        data[i] ^= streamKey[(streamKey[a] + streamKey[b]) % streamKey.length];
    }
}

ubyte[] generateKey(const(ubyte)[] password)
{
    ubyte[] key = new ubyte[256];

    import std.range : iota;
    import std.algorithm : each;

    iota(256).each!(i => key[i] = cast(ubyte) i);

    uint num = 0;

    foreach (i; 0 .. 256)
    {
        num = (num + key[i] + password[i % password.length]) % 256;

        import std.algorithm : swap;

        swap(key[i], key[num]);
    }

    return key;
}

// unused, no idea what grfeditor is apparently trying to do with it
ubyte[] hashPassword(const(ubyte)[] password, uint initialSalt = uint.max)
in (password.length >= 4 && password.length <= 256, "Password must be between 4 and 256 characters long")
{
    import std.random : uniform;

    uint salt = initialSalt == uint.max ? uniform(0, uint.max) : initialSalt;

    // First 4 bytes are used by the salt
    ubyte[] saltedHash = new ubyte[260];
    ubyte[] hashSlice = saltedHash[4 .. 260];

    import std.range : iota;
    import std.algorithm : each;

    iota(256).each!(i => hashSlice[i] = cast(ubyte) i);

    uint num = 0;

    foreach (i; 0 .. 256)
    {
        num = (num + hashSlice[i] + password[i % password.length]) % 256;

        import std.algorithm : swap;

        swap(hashSlice[i], hashSlice[num]);
    }

    foreach (i; 0 .. 256)
    {
        hashSlice[i] ^= salt % 256;
        salt *= 17;
    }

    import std.bitmanip : nativeToLittleEndian;

    // Since GRFEditor was created on windows for windows it will
    // store this number in little endian
    saltedHash[0 .. 4] = nativeToLittleEndian(salt);

    return saltedHash;
}

// unused, no idea what grfeditor is apparently trying to do with it
ubyte[] generateEncryptionKey(const(ubyte)[] saltedHash) pure
in (saltedHash.length == 260, "Key must be 260 bytes long")
{
    ubyte[] key = saltedHash[4 .. 260].dup;

    import std.bitmanip : littleEndianToNative;

    // Since GRFEditor was created on windows for windows it will
    // store this number in little endian
    uint salt = littleEndianToNative!uint(saltedHash[0 .. 4]);

    foreach (i; 0 .. 256)
    {
        key[i] ^= salt % 256;
        salt *= 17;
    }

    return key;
}

