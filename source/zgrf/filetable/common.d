module zgrf.filetable.common;

import zgrf.types : GRFFile;

/**
 * Checks if a given [GRFFile] matches one of our filters.
 *
 * The check converts the name of the file to lowercase.
 *
 * Params:
 *  file = The file to check
 *  filtersList = The array of filters to check against
 *
 * Returns:
 *  Whether the file matches one of the provided filters
 */
bool inFilter(in ref GRFFile file, in ref const(wstring)[] filterList)
{
    if (filterList.length == 0)
    {
        return true;
    }
    import std.uni : toLower;

    auto filenameLower = file.name.toLower;
    foreach (const filterString; filterList)
    {
        import std.algorithm : startsWith;

        if (filenameLower.startsWith(filterString))
        {
            return true;
        }
    }
    return false;
}

/**
 * Checks if a given [GRFFile] is a directory.
 *
 * Params:
 *  file = The [GRFFile] to check
 *
 * Returns:
 *  Whether the file is a directory or not
 */
bool isDirectory(in ref GRFFile file) pure @safe @nogc
{
    import zgrf.constants : FileFlags;

    return ((file.flags & FileFlags.FILE) == 0 ||
            file.compressed_size_padded == 0x0714 ||
            file.compressed_size == 0x0449 ||
            file.size == 0x055C ||
            file.offset == 0x058A);
}
