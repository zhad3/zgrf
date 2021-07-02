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
        dst = cast(ubyte[]) zlib_uncompress(srcbuf, destlen);
    }
    return dst;
}

// Taken directly from std/zlib.d
// This implementation does not treat Z_BUF_ERROR as an error that should be thrown
private void[] zlib_uncompress(const(void)[] srcbuf, size_t destlen = 0u, int winbits = 15)
{
    import etc.c.zlib;
    import std.zlib : ZlibException;
    import std.conv : to;
    int err;
    ubyte[] destbuf;

    if (!destlen)
        destlen = srcbuf.length * 2 + 1;

    etc.c.zlib.z_stream zs;
    zs.next_in = cast(typeof(zs.next_in)) srcbuf.ptr;
    zs.avail_in = to!uint(srcbuf.length);
    err = etc.c.zlib.inflateInit2(&zs, winbits);
    if (err)
    {
        throw new ZlibException(err);
    }

    size_t olddestlen = 0u;

    loop:
    while (true)
    {
        destbuf.length = destlen;
        zs.next_out = cast(typeof(zs.next_out)) &destbuf[olddestlen];
        zs.avail_out = to!uint(destlen - olddestlen);
        olddestlen = destlen;

        err = etc.c.zlib.inflate(&zs, Z_NO_FLUSH);
        switch (err)
        {
            case Z_OK:
                destlen = destbuf.length * 2;
                continue loop;

            case Z_BUF_ERROR:
            case Z_STREAM_END:
                destbuf.length = zs.total_out;
                err = etc.c.zlib.inflateEnd(&zs);
                if (err != Z_OK)
                    throw new ZlibException(err);
                return destbuf;

            default:
                etc.c.zlib.inflateEnd(&zs);
                throw new ZlibException(err);
        }
    }
    assert(0, "Unreachable code");
}
