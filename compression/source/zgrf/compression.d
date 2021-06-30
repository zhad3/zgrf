module zgrf.compression;

import lzma;

extern (C) private void* szAlloc(void* p, size_t size)
{
    import core.stdc.stdlib : malloc;

    return malloc(size);
}

extern (C) private void szFree(void* p, void* address)
{
    import core.stdc.stdlib : free;

    free(address);
}

private ISzAlloc szAllocLzma = {&szAlloc, &szFree};

/**
 * Uncompresses data. If the first byte of srcbuf is 0 then
 * LZMA will be used to uncompress the data. Otherwise
 * uses zlib.
 *
 * Params:
 *  srcbuf = The compressed data
 *  destlen = The uncompressed size
 *
 * Returns:
 *  The uncompressed data
 */
ubyte[] uncompress(const(ubyte)[] srcbuf, size_t destlen = 0u)
{
    ubyte[] dst;
    if (destlen == 0)
    {
        destlen = srcbuf.length * 2 + 1;
    }

    if (srcbuf[0] == 0)
    {
        if (srcbuf.length < LZMA_PROPS_SIZE + 1)
        {
            return dst;
        }
        ELzmaStatus status;
        SizeT destlen2 = destlen;
        SizeT pack_size = srcbuf.length - LZMA_PROPS_SIZE - 1;
        dst = new ubyte[destlen];
        int ret = LzmaDecode(
                dst.ptr,
                &destlen2,
                cast(const(Byte*))(&srcbuf[LZMA_PROPS_SIZE + 1]),
                &pack_size,
                cast(const(Byte*))(&srcbuf[1]),
                LZMA_PROPS_SIZE,
                ELzmaFinishMode.LZMA_FINISH_END,
                &status,
                &szAllocLzma
        );
        if (ret != SZ_OK)
        {
        }
    }
    else
    {
        import std.zlib : zlib_uncompress = uncompress;

        dst = cast(ubyte[]) zlib_uncompress(srcbuf, destlen);
    }
    return dst;
}
