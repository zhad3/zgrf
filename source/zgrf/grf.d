module zgrf.grf;

import zgrf.types;

/**
 * Parses the header of the given GRF.
 *
 * The header will be available in the input grf
 * class via grf.header.
 *
 * Params:
 *  grf = The GRF file to read the header from
 *
 * Returns:
 *  Input grf for easy chaining
 */
ref GRF readHeader(return ref GRF grf)
in (grf.filehandle.isOpen(), "Filehandle of grf file must be open to read header")
{
    if (grf.header.grfVersion > 0)
    {
        // Header has already been parsed
        return grf;
    }
    import core.stdc.stdio : SEEK_SET;

    grf.filehandle.seek(0, SEEK_SET);

    import zgrf.constants : HEADER_LEN;

    ubyte[HEADER_LEN] buffer;
    grf.filehandle.rawRead(buffer);

    import std.bitmanip : littleEndianToNative;

    grf.header.signature = buffer[0 .. 15];
    grf.header.encryption = buffer[15 .. 30];
    grf.header.filetableOffset = littleEndianToNative!uint(buffer[30 .. 34]) + HEADER_LEN;
    grf.header.seed = littleEndianToNative!uint(buffer[34 .. 38]);
    grf.header.rawFilecount = littleEndianToNative!uint(buffer[38 .. 42]);
    grf.header.grfVersion = littleEndianToNative!uint(buffer[42 .. 46]);
    grf.header.filecount = grf.header.rawFilecount - grf.header.seed - 7;

    return grf;
}

/// ditto
ref VirtualGRF readHeader(return ref VirtualGRF vgrf)
{
    foreach (ref grf; vgrf.grfs)
    {
        grf.readHeader();
    }

    return vgrf;
}

/**
 * Parses the filetable of the given grf.
 * If filters is provided then only the files which
 * matches the filters will be loaded.
 *
 * The filters do not support wildcards it just
 * checks if the filename starts with the same
 * characters.
 *
 * Params:
 *  grf = The grf to read the filetable from
 *  filters = Array of filters
 *
 * Returns:
 *  Input grf for easy chaining
 */
ref GRF readFiletable(return ref GRF grf, const(wstring)[] filters = [])
in (grf.filehandle.isOpen(), "Filehandle of grf file must be open to read filetable")
in (grf.header.grfVersion > 0, "GRF header needs to be parsed")
{
    if (grf.header.grfVersion > 0x100 && grf.header.grfVersion < 0x200)
    {
        import zgrf.filetable.version1xx;

        fill(grf, filters);
    }
    else if (grf.header.grfVersion >= 0x200)
    {
        import zgrf.filetable.version2xx;

        fill(grf, filters);
    }

    return grf;
}

/// ditto
ref VirtualGRF readFiletable(return ref VirtualGRF vgrf, const(wstring)[] filters = [])
{
    foreach (ref grf; vgrf.grfs)
    {
        if (grf.header.grfVersion > 0x100 && grf.header.grfVersion < 0x200)
        {
            import zgrf.filetable.version1xx;

            fill(grf, vgrf.files, filters);
        }
        else
        {
            import zgrf.filetable.version2xx;

            fill(grf, vgrf.files, filters);
        }
    }

    return vgrf;
}

/**
 * Parses a grf file given optional filters.
 *
 * Calls [readHeader] and [readFiletable] on the input grf.
 *
 * Params:
 *  grf = The GRF file to parse
 *  filters = The filters to use when parsing the filetable
 *
 * Returns:
 *  Input grf for easy chaining
 */
ref GRF parse(return ref GRF grf, const(wstring)[] filters = [])
in (grf.filehandle.isOpen(), "Filehandle of grf file must be open valid to be able to parse")
{
    return grf.readHeader().readFiletable(filters);
}

/// ditto
ref VirtualGRF parse(return ref VirtualGRF vgrf, const(wstring)[] filters = [])
{
    return vgrf.readHeader().readFiletable(filters);
}

/**
 * Get the unencrypted and uncompressed data of a file inside the input grf.
 *
 * Params:
 *  grf = The grf to read the file from
 *  file = The metadata about the file to be read
 *
 * Returns:
 *  The unencrypted and uncompressed file data
 */
ubyte[] getFileData(ref GRF grf, ref GRFFile file)
in (grf.filehandle.isOpen(), "Filehandle of grf file must be open to read file data")
{
    import zgrf.constants : HEADER_LEN, FileFlags;

    grf.filehandle.seek(file.offset + HEADER_LEN);
    ubyte[] encryptedData = new ubyte[file.compressed_size_padded];
    grf.filehandle.rawRead(encryptedData);

    if (file.compressed_size_padded % 8 > 0)
    {
        // If the encrypted (supposibly padded) filesize is not a multiple of 8 bytes
        // just fill the data up with zeros until it is
        encryptedData.length += 8 - (file.compressed_size_padded % 8);
    }

    ubyte[] decryptedData;
    if (file.flags & FileFlags.MIXCRYPT)
    {
        import zgrf.crypto.mixcrypt;

        decryptedData = zgrf.crypto.mixcrypt.decrypt(encryptedData, [0, 0, 0, 0, 0, 0, 0, 0],
                file.compressed_size);
    }
    else if (file.flags & FileFlags.DES)
    {
        import zgrf.crypto.desbroken;

        decryptedData = zgrf.crypto.desbroken.decrypt(encryptedData, [0, 0, 0, 0, 0, 0, 0, 0],
                file.compressed_size);
    }
    else
    {
        decryptedData = encryptedData;
    }

    import zgrf.compression : uncompress;

    file.data = uncompress(decryptedData, file.size);

    return file.data;
}

/// ditto
ubyte[] getFileData(ref GRF grf, const wstring filename)
{
    import std.zlib;

    const uint hash = crc32(0, filename);
    if (hash in grf.files)
    {
        return getFileData(grf, grf.files[hash]);
    }
    else
    {
        return [];
    }
}

/// ditto
ubyte[] getFileData(ref VirtualGRF vgrf, const wstring filename)
{
    import std.zlib;

    const uint hash = crc32(0, filename);
    if (hash in vgrf.files)
    {
        auto file = vgrf.files[hash];
        return getFileData(*file.grf, file);
    }
    else
    {
        return [];
    }
}

/**
 * Open the internal file handle of the grf.
 *
 * Params:
 *  grf = The grf to open the filehandle for
 */
void open(ref GRF grf)
in (!grf.filehandle.isOpen(), "Filehandle is already open")
{
    grf.filehandle.open(grf.filename, "rb");
}

/// ditto
void open(ref VirtualGRF vgrf)
{
    foreach (ref grf; vgrf.grfs)
    {
        grf.open();
    }
}

/**
 * Close the internal file handle of the grf.
 *
 * Params:
 *  grf = The grf to close the filehandle for
 */
void close(ref GRF grf)
in (grf.filehandle.isOpen(), "Filehandle is not open, cannot close")
{
    grf.filehandle.close();
}

/// ditto
void close(ref VirtualGRF vgrf)
{
    foreach (ref grf; vgrf.grfs)
    {
        grf.close();
    }
}

/*unittest
{
    VirtualGRF testgrf = VirtualGRF(["../zextractor/data.grf", "../zextractor/rdata.grf"]);
    scope (exit)
        testgrf.close();

    //testgrf.parse();
    testgrf.readHeader();
    import std.stdio : writeln, writefln;

    writefln("Filetable offset: %d", testgrf.grfs[0].header.filetableOffset);

    //writeln(testgrf.header);
    //writeln(testgrf.filesize);

    testgrf.readFiletable();

    import std.stdio : File;

    auto f = File("output_0x102", "w+");

    import std.range : appender;
    import std.format : formattedWrite;

    foreach (GRFFile file; testgrf.files)
    {
        auto app = appender!wstring;
        for (auto x = 0; x < file.rawName.length; ++x)
        {
            if (file.rawName[x] == 0)
            {
                break;
            }
            app.put(file.rawName[x]);
        }
        app.put("\n");
        app.put(file.name);
        app.put("\n");
        app.formattedWrite("Hash: %X\n", file.hash);
        app.formattedWrite("Filesize: %d\n", file.size);
        app.formattedWrite("Filesize (compressed): %d\n", file.compressed_size);
        app.formattedWrite("Filesize (compressed, padded): %d\n", file.compressed_size_padded);
        app.formattedWrite("Offset: %d\n", file.offset);
        app.formattedWrite("Offset FT: %d\n", file.offset_ft);
        app.put("===\n");
        f.write(app.data);
    }
    f.close();

    //ubyte[] filedata = testgrf.getFileData("data\\texture\\유저인터페이스\\btn_cancel.bmp"w);
    ubyte[] filedata = testgrf.getFileData("data\\texture\\기타마을내부\\sage_ta003.bmp"w);
    f = File("output_file_test.bmp", "w+");
    f.rawWrite(filedata);
    f.close();
}*/
