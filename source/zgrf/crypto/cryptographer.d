module zgrf.crypto.cryptographer;

/**
 * Interface for cryptography algorithms.
*/
interface Cryptographer {

    /**
     *  Encrypts data using a specific key.
     *  Params:
     *      data =  The data array to be encrypted
     *      key =   The key used to encrypt the data
     *  Returns: An array of bytes containing the encrypted data
    */
    ubyte[] encrypt(const ubyte[] data, const ubyte[] key);

    /**
        Decrypts data using a specific key.
        Params:
            data =  The data array to be decrypted
            key =   The key used to decrypt the data
        Returns: An array of bytes containing the dectrypted data
    */
    ubyte[] decrypt(const ubyte[] data, const ubyte[] key);
}
