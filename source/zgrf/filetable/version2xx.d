module zgrf.filetable.version2xx;

import core.stdc.stdio : SEEK_SET, SEEK_END;
import std.system : Endian;
import std.zlib : crc32;
import std.uni : toLower;
import std.bitmanip : peek, read;

import zgrf.constants;
import zgrf.types;
import zgrf.filetable.common;

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
in (grf.header.grfVersion >= 0x200, "Minimum GRF version allowed for this filetable is 0x200")
{
    grf.filehandle.seek(grf.header.filetableOffset, SEEK_SET);

    ubyte[] filetableSizesBuf = new ubyte[uint.sizeof * 2];
    grf.filehandle.rawRead(filetableSizesBuf);

    const compressed_size = filetableSizesBuf.read!(uint, Endian.littleEndian);
    const uncompressed_size = filetableSizesBuf.read!(uint, Endian.littleEndian);

    ubyte[] zbuffer = new ubyte[compressed_size];

    grf.filehandle.rawRead(zbuffer);

    ulong offset = 0;

    import zgrf.compression : uncompress;

    ubyte[] buffer = uncompress(zbuffer, uncompressed_size);
    assert(buffer.length == uncompressed_size);

    if (filters.length > 0)
    {
        foreach (i; 0 .. grf.header.filecount)
        {
            GRFFile file = extractFile(buffer, offset, grf.header.grfVersion);
            file.offset_ft += grf.header.filetableOffset + HEADER_LEN;
            file.grf = &grf;
            if (inFilter(file, filters) && !isDirectory(file))
            {
                file.hash = crc32(0, file.name.toLower);
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
                file.grf = &grf;
                file.hash = crc32(0, file.name.toLower);
                files.require(file.hash, file);
            }
        }
    }
}

/// ditto
void fill(ref GRF grf, const(wstring)[] filters = [])
in (grf.filehandle.isOpen(), "Filehandle must be open to read the filetable")
in (grf.header.grfVersion >= 0x200, "Minimum GRF version allowed for this filetable is 0x200")
{
    fill(grf, grf.files, filters);
}

private GRFFile extractFile(ref ubyte[] buffer, ref ulong offset, uint /*grfVersion*/ ) pure
{

    GRFFile file;

    file.offset_ft = offset;

    import core.stdc.string : strlen;

    auto filenameLength = strlen(cast(char*)(buffer.ptr + offset)) + 1;
    import std.conv : to;

    assert(filenameLength <= FILENAME_LENGTH,
            "Filename too long (" ~ filenameLength.to!string ~ ") at offset " ~ offset.to!string);

    file.rawName = buffer[offset .. (offset + filenameLength)].dup;

    offset += filenameLength;

    file.compressed_size = buffer.peek!(uint, Endian.littleEndian)(&offset);
    file.compressed_size_padded = buffer.peek!(uint, Endian.littleEndian)(&offset);
    file.size = buffer.peek!(uint, Endian.littleEndian)(&offset);
    file.flags = cast(FileFlags) buffer.peek!ubyte(&offset);
    file.offset = buffer.peek!(uint, Endian.littleEndian)(&offset);
    import zencoding.windows949 : fromWindows949;

    file.name = fromWindows949(file.rawName);

    return file;
}
