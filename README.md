# zgrf

Library to interact with Gravity's resource and patch file (GRF/GPF).

## Documentation
The documentation can be found here: https://zgrf.dpldocs.info

## Building
### Requirements
- DMD, LDC or GDC

Additionally in order to compile the LZMA library a c compiler is required.
For linux that would be
- gcc

and for Windows
- msvc

To obtain msvc on Windows you will need the [Build Tools for Visual Studio](https://visualstudio.microsoft.com/de/downloads/#build-tools-for-visual-studio-2019).

### Compiling
#### Linux
If everything is present simply run  
`dub build`

#### Windows
From within the Developer Console that will be available after installing the Build Tools  
run `dub build`

## Example
Extract all files in a grf/gpf
```d
import zgrf;

int main(string[] args)
{
    GRF grf = GRF("data.grf");

    scope(exit)
        grf.close();

    // At this point nothing is yet loaded
    // Let's parse the GRF and load the header + filetable
    grf.parse();

    // We now have access to the header and filetable
    import std.stdio : writefln;
    writefln("GRF Version: 0x%0X", grf.header.grfVersion);

    // Let's extract all files
    ulong fileindex = 0;
    ulong filecount = grf.files.length;
    foreach (ref GRFFile file; grf.files)
    {
        import std.path : dirName;

        // Filenames are stored with Windows paths
        version(Posix)
        {
            import std.array : replace;
            wstring fullpath = file.name.replace("\\"w, "/"w);
            wstring path = dirName(fullpath);
        }
        else
        {
            // Windows, no need to change anything
            wstring fullpath = file.name;
            wstring path = dirName(file.name);
        }

        // Print some progress
        writefln("Extracting (%d/%d): %s", fileindex + 1, filecount, fullpath);

        import std.file : mkdirRecurse;
        import std.utf : toUTF8;
        import std.typecons : No;

        mkdirRecurse(path.toUTF8);

        // Unencrypt und decompress file data. We also disable cache.
        const data = file.getFileData(No.useCache);

        import std.stdio : File;

        auto fout = File(fullpath, "w+");
        fout.rawWrite(data);
        fout.close();

        fileindex++;
    }
}
```
