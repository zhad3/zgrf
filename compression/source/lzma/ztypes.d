/* 7zTypes.h -- Basic types
2013-11-12 : Igor Pavlov : Public domain */

module lzma.ztypes;

extern (C):

enum {
    SZ_OK = 0,

    SZ_ERROR_DATA = 1,
    SZ_ERROR_MEM = 2,
    SZ_ERROR_CRC = 3,
    SZ_ERROR_UNSUPPORTED = 4,
    SZ_ERROR_PARAM = 5,
    SZ_ERROR_INPUT_EOF = 6,
    SZ_ERROR_OUTPUT_EOF = 7,
    SZ_ERROR_READ = 8,
    SZ_ERROR_WRITE = 9,
    SZ_ERROR_PROGRESS = 10,
    SZ_ERROR_FAIL = 11,
    SZ_ERROR_THREAD = 12,

    SZ_ERROR_ARCHIVE = 16,
    SZ_ERROR_NO_ARCHIVE = 17
}

alias SRes = int;
alias WRes = int;

alias Byte = ubyte;
alias Int16 = short;
alias UInt16 = ushort;
alias Int32 = int;
alias UInt32 = uint;
alias Int64 = long;
alias UInt64 = ulong;
alias SizeT = size_t;
alias Bool = bool;
enum {
    False = 0,
    True = 1
}

/* The following interfaces use first parameter as pointer to structure */

struct IByteIn {
    Byte function(void *p) Read; /* reads one byte, returns 0 in case of EOF or error */
}

struct IByteOut {
    void function(void *p, Byte b) Write;
}

struct ISeqInStream {
    SRes function(void *p, void *buf, size_t *size) Read;
    /* if (input(*size) != 0 && output(*size) == 0) means end_of_stream.
       (output(*size) < input(*size)) is allowed */
}

/* it can return SZ_ERROR_INPUT_EOF */
SRes SeqInStream_Read(ISeqInStream *stream, void *buf, size_t size);
SRes SeqInStream_Read2(ISeqInStream *stream, void *buf, size_t size, SRes errorType);
SRes SeqInStream_ReadByte(ISeqInStream *stream, Byte *buf);

struct ISeqOutStream {
    size_t function(void *p, const void *buf, size_t size) Write;
    /* Returns: result - the number of actually written bytes.
       (result < size) means error */
}

enum ESzSeek {
    SZ_SEEK_SET = 0,
    SZ_SEEK_CUR = 1,
    SZ_SEEK_END = 2
}

struct ISeekInStream {
    SRes function(void *p, void *buf, size_t *size) Read; /* same as ISeqInStream::Read */
    SRes function(void *p, Int64 *pos, ESzSeek origin) Seek;
}

struct ILookInStream {
  SRes function(void *p, const void **buf, size_t *size) Look;
    /* if (input(*size) != 0 && output(*size) == 0) means end_of_stream.
       (output(*size) > input(*size)) is not allowed
       (output(*size) < input(*size)) is allowed */
  SRes function(void *p, size_t offset) Skip;
    /* offset must be <= output(*size) of Look */

  SRes function(void *p, void *buf, size_t *size) Read;
    /* reads directly (without buffer). It's same as ISeqInStream::Read */
  SRes function(void *p, Int64 *pos, ESzSeek origin) Seek;
}

SRes LookInStream_LookRead(ILookInStream *stream, void *buf, size_t *size);
SRes LookInStream_SeekTo(ILookInStream *stream, UInt64 offset);

/* reads via ILookInStream::Read */
SRes LookInStream_Read2(ILookInStream *stream, void *buf, size_t size, SRes errorType);
SRes LookInStream_Read(ILookInStream *stream, void *buf, size_t size);

enum LookToRead_BUF_SIZE = (1 << 14);

struct CLookToRead {
    ILookInStream s;
    ISeekInStream *realStream;
    size_t pos;
    size_t size;
    Byte[1 << 14] buf;
}

void LookToRead_CreateVTable(CLookToRead *p, int lookahead);
void LookToRead_Init(CLookToRead *p);

struct CSecToLook {
    ISeqInStream s;
    ILookInStream *realStream;
}

void SecToLook_CreateVTable(CSecToLook *p);

struct CSecToRead {
    ISeqInStream s;
    ILookInStream *realStream;
}

void SecToRead_CreateVTable(CSecToRead *p);

struct ICompressProgress {
    SRes function(void *p, UInt64 inSize, UInt64 outSize) Progress;
    /* Returns: result. (result != SZ_OK) means break.
       Value (UInt64)(Int64)-1 for size means unknown value. */
}

struct ISzAlloc {
    void* function(void *p, size_t size) Alloc;
    void function(void *p, void *address) Free;
}

void IAlloc_Alloc(ISzAlloc *p, size_t size) { p.Alloc(p, size); }
void IAlloc_Free(ISzAlloc *p, void *a) { p.Free(p, a); }

