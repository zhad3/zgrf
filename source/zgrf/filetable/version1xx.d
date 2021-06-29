module zgrf.filetable.version1xx;

import core.stdc.stdio : SEEK_SET, SEEK_END;
import std.zlib : crc32;
import std.uni : toLower;

import zgrf.constants;
import zgrf.types;
import zgrf.filetable.common;

private const(wstring)[4] specialFileExtensions = [
    ".gnd",
    ".gat",
    ".act",
    ".str"
];

private bool hasSpecialExtension(const wstring name)
{
    import std.uni : toLower;
    import std.algorithm : endsWith;

    auto lowerCaseName = name.toLower;
    foreach (ext; specialFileExtensions)
    {
        if (lowerCaseName.endsWith(ext))
        {
            return true;
        }
    }
    return false;
}

/**
 * Fills the provided GRFFiletable files with [GRFFile] of the input grf.
 *
 * Params:
 *  grf = The grf to read the files from
 *  files = The target filetable to store the [GRFFile] to
 *  filters = The filters to check for when reading the files
 */
void fill(ref GRF grf, ref GRFFiletable files, const(wstring)[] filters = [])
in (grf.filehandle.isOpen(), "Filehandle must be open to read the filetable")
in (grf.header.grfVersion <= 0x103, "Maximum GRF version allowed for this filetable is 0x103")
in (grf.filesize > grf.header.filetableOffset, "GRF filesize < Filetable offset")
{
    grf.filehandle.seek(grf.header.filetableOffset, SEEK_SET);

    const filetablesize = grf.filesize - grf.header.filetableOffset;
    ubyte[] buffer = new ubyte[filetablesize];
    grf.filehandle.rawRead(buffer);

    ulong offset = 0;

    if (filters.length > 0)
    {
        foreach (i; 0 .. grf.header.filecount)
        {
            GRFFile file = extractFile(buffer, offset, grf.header.grfVersion);
            if (inFilter(file, filters) && !isDirectory(file))
            {
                file.offset_ft += grf.header.filetableOffset + HEADER_LEN;
                file.hash = crc32(0, file.name.toLower);
                file.grf = &grf;
                if (hasSpecialExtension(file.name))
                {
                    file.flags |= FileFlags.DES;
                }
                else
                {
                    file.flags |= FileFlags.MIXCRYPT;
                }

                files.require(file.hash, file);
            }
        }
    }
    else
    {
        foreach (i; 0 .. grf.header.filecount)
        {
            GRFFile file = extractFile(buffer, offset, grf.header.grfVersion);
            if (!isDirectory(file))
            {
                file.offset_ft += grf.header.filetableOffset + HEADER_LEN;
                file.hash = crc32(0, file.name.toLower);
                file.grf = &grf;
                if (hasSpecialExtension(file.name))
                {
                    file.flags |= FileFlags.DES;
                }
                else
                {
                    file.flags |= FileFlags.MIXCRYPT;
                }
                files.require(file.hash, file);
            }
        }
    }
}

/// ditto
void fill(ref GRF grf, const(wstring)[] filters = [])
in (grf.filehandle.isOpen(), "Filehandle must be open to read the filetable")
in (grf.header.grfVersion <= 0x103, "Maximum GRF version allowed for this filetable is 0x103")
{
    fill(grf, grf.files, filters);
}

private GRFFile extractFile(ref ubyte[] buffer, ref ulong offset, uint grfVersion) pure
{
    import std.system : Endian;
    import std.bitmanip : peek;

    GRFFile file;

    file.offset_ft = offset;

    const filenameLength = buffer.peek!(uint, Endian.littleEndian)(&offset);
    assert(filenameLength <= FILENAME_LENGTH);

    ulong filenameLength2;

    if (grfVersion < 0x101)
    {
        import core.stdc.string : strlen;

        filenameLength2 = strlen(cast(char*)(buffer.ptr + offset));
    }
    else
    {
        offset += 2;
        filenameLength2 = filenameLength - (filenameLength % 8);
    }

    auto filenameBuffer = buffer[offset .. (offset + filenameLength2)];

    import zgrf.bits : swapNibbles;

    swapNibbles(filenameBuffer);

    if (grfVersion >= 0x101) {
        import zgrf.crypto.mixcrypt;

        filenameBuffer = decrypt(filenameBuffer, [], filenameLength2);
        offset -= 2;
    }
    file.rawName = filenameBuffer.dup;

    offset += filenameLength;

    file.compressed_size = buffer.peek!(uint, Endian.littleEndian)(&offset);
    file.compressed_size_padded = buffer.peek!(uint, Endian.littleEndian)(&offset);
    file.size = buffer.peek!(uint, Endian.littleEndian)(&offset);
    file.flags = cast(FileFlags) buffer.peek!ubyte(&offset);
    file.offset = buffer.peek!(uint, Endian.littleEndian)(&offset);
    import zencoding.windows949 : fromWindows949;

    file.name = fromWindows949(file.rawName);

    // Update compressed sizes
    file.compressed_size -= file.size - 0x02CB;
    file.compressed_size_padded -= 0x92CB;

    return file;
}
