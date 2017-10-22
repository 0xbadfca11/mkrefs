//======================================================================
//
// Fmifs.h
//
// By Mark Russinovich
// Systems Internals
// http://www.sysinternals.com
//
// Typedefs and definitions for using chkdsk and formatex
// functions exported by the fmifs.dll library.
//
//======================================================================


//
// Output command
//
typedef struct {
	DWORD Lines;
	PCHAR Output;
} TEXTOUTPUT, *PTEXTOUTPUT;

//
// Callback command types
//
typedef enum {
	PROGRESS,
	DONEWITHSTRUCTURE,
	UNKNOWN2,
	UNKNOWN3,
	UNKNOWN4,
	UNKNOWN5,
	INSUFFICIENTRIGHTS,
	UNKNOWN7,
	UNKNOWN8,
	UNKNOWN9,
	UNKNOWNA,
	DONE,
	UNKNOWNC,
	UNKNOWND,
	OUTPUT,
	STRUCTUREPROGRESS
} CALLBACKCOMMAND;

//
// FMIFS callback definition
//
typedef BOOLEAN (__stdcall *PFMIFSCALLBACK)( CALLBACKCOMMAND Command, DWORD SubAction, PVOID ActionInfo ); 

//
// Chkdsk command in FMIFS
//
typedef VOID (__stdcall *PCHKDSK)( PWCHAR DriveRoot, 
						PWCHAR Format,
						BOOL CorrectErrors, 
						BOOL Verbose, 
						BOOL CheckOnlyIfDirty,
						BOOL ScanDrive, 
						PVOID Unused2, 
						PVOID Unused3,
						PFMIFSCALLBACK Callback );

//
// Format command in FMIFS
//

// media flags
#define FMIFS_HARDDISK 0xC
#define FMIFS_FLOPPY   0x8

typedef VOID (__stdcall *PFORMATEX)( PWCHAR DriveRoot,
						  DWORD MediaFlag,
						  PWCHAR Format,
						  PWCHAR Label,
						  BOOL QuickFormat,
						  DWORD ClusterSize,
						  PFMIFSCALLBACK Callback );

//
// Enable/Disable volume compression
//
typedef BOOLEAN (__stdcall *PENABLEVOLUMECOMPRESSION)(PWCHAR DriveRoot,
							BOOL Enable );
