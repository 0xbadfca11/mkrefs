# MKREFS
Temporary patching in-memory to enable format with ReFS.
```
Formats a disk for use with Windows.

MKREFS volume [/V:label] [/A:{4096 | 64K}] [/I:{enable | disable}] [/X]

  /V:label        Specifies the volume label.
  /X              Forces the volume to dismount first if necessary.  All opened
                  handles to the volume would no longer be valid.
  /A:size         Overrides the default allocation unit size.
                  ReFS supports 4096, 64K.
  /I:state        Specifies whether integrity should be enabled on
                  the new volume. "state" is either "enable" or "disable"
                  Integrity is enabled on storage that supports data redundancy
                  by default.
  /FS:            Ignore.
  /Q              Ignore. Always performs quick format.
```
## License
MIT License  
Except `FMIFS.H`. That file [Copyright © 1998 Mark Russinovich](https://web.archive.org/web/20051130041735/http://www.sysinternals.com/SourceCode/fmifs.html)
