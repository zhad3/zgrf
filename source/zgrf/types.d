module zgrf.types;

import zgrf.constants;

/// Holds information that is present in all GRF files.
struct GRFHeader
{
    /// "Master of Magic"
    ubyte[15] signature;
    /**
     * Either [0x00, 0x01, 0x03, ..., 0x0C, 0x0D, 0x0E] => Use Mixcrypt
     * or     [0x00, 0x00, 0x00, ..., 0x00, 0x00, 0x00] => Not encrypted
     */
    ubyte[15] encryption;
    /// Offset of the filetable after the header: offset + GRFHeader.sizeof
    uint filetableOffset;
    /// Unknown
    uint seed;
    /// actual filecount = rawFilecount - seed - 7
    uint rawFilecount;
    /// actual filecount
    uint filecount;
    /// Version of the GRF. Either 0x102, 0x103 or 0x200.
    uint grfVersion;
}

/// Holds information about a single GRFFile
struct GRFFile
{
    /// Compressed filesize using either zlib or lzma
    uint compressed_size;
    /// Same as above with extra padding for the DES algorithm
    uint compressed_size_padded;
    /// Uncompressed size
    uint size;
    /// Offset of the file after the file header
    uint offset;
    /// See zgrf.constants : FileFlags
    FileFlags flags;
    /// Offset in filetable
    ulong offset_ft;
    /// Filename
    wstring name;
    /// Raw filename
    ubyte[] rawName;
    /// Data content
    ubyte[] data;
    /// GRF where this file is saved in
    GRF* grf;
}

/// Hashmap of files
alias GRFFiletable = GRFFile[wstring];

/**
 * Holds information about a GRF file.
 *
 * Examples:
 * --------
 * import zgrf.types;
 *
 * GRF grf = GRF("data.grf");
 * --------
 */
struct GRF
{
    import std.stdio : File;

    /// Filehandle that is used to read any data from
    File filehandle;
    /// Filename of the GRF file
    string filename;
    /// Filesize of the GRF file
    size_t filesize;
    /// GRF Header. Will be filled once [zgrf.grf.readHeader] is called.
    GRFHeader header;
    /// Associative array of the files. Will be filled once [zgrf.grf.readFiletable] is called.
    GRFFiletable files;

    /**
     * Opens the filehandle and stores the filesize
     *
     * Params:
     *  name = Filename of the GRF
     */
    this(string name)
    {
        filename = name;
        filehandle = File(filename, "rb");
        import core.stdc.stdio : SEEK_SET, SEEK_END;

        filehandle.seek(0, SEEK_END);
        filesize = filehandle.tell();
        filehandle.seek(0, SEEK_SET);
    }
}

/**
 * Holds information about multiple GRF.
 * Use this struct if you wish to open multiple GRF files
 * but retain a single GRF. Essentially merging the two GRF
 * files.
 *
 * Examples:
 * -----------
 * import zgrf.types;
 *
 * // rdata.grf is loaded first and any files that are not in rdata.grf
 * // are loaded from data.grf
 * VirtualGRF grf = VirtualGRF(["rdata.grf", "data.grf"]);
 * ----------
 */
struct VirtualGRF
{
    /// The GRFs in this VirtualGRF
    GRF[] grfs;
    /// The merged filetable from the GRFs
    GRFFiletable files;

    /// See [GRF]
    this(string[] filenames)
    {
        foreach(filename; filenames)
        {
            grfs ~= GRF(filename);
        }
    }
}
