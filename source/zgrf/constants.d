module zgrf.constants;

/// Length of the header
enum uint HEADER_LEN = 46;

/// Length of the file struct inside the filetable
enum uint FILE_LEN = 0;

/**
 * The maximum allowed filename length. This used to be 100,
 * however observing newer files it exceeded that number.
 */
enum uint FILENAME_LENGTH = 256;

/**
 * FILE specifies that an entry is a file. If not set it is a directory.
 * MIXCRYPT specifies that the file is encrypted using the Mixcrypt algorithm.
 * DES specifies that the first 0x14 bytes of the file are encrypted using the DESBroken algorithm.
 */
enum FileFlags : ubyte
{
    FILE = 0x1,
    MIXCRYPT = 0x2,
    DES = 0x4
}
