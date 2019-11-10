#define WIN32_LEAN_AND_MEAN
#define STRICT_GS_ENABLED
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _ATL_NO_DEFAULT_LIBS
#define _ATL_NO_WIN_SUPPORT
#define _CRTDBG_MAP_ALLOC
#include <windows.h>
#include <dbghelp.h>
#include <pathcch.h>
#include <winioctl.h>
#include <clocale>
#include <cstring>
#include <optional>
#include <atlbase.h>
#include <atlchecked.h>
#include <conio.h>
#include <crtdbg.h>
#include "FMIFS.H"
#pragma comment(lib, "dbghelp")
#pragma comment(lib, "pathcch")

[[noreturn]]
void die()
{
	PWSTR msg;
	ATLENSURE(FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, GetLastError(), 0, reinterpret_cast<PWSTR>(&msg), 0, nullptr));
	fputws(msg, stderr);
	_CrtDbgBreak();
	ExitProcess(EXIT_FAILURE);
}
void EnableRefsFormat()
{
	WCHAR dbghelp[MAX_PATH];
	ATLENSURE(GetModuleFileNameW(nullptr, dbghelp, ARRAYSIZE(dbghelp)));
	ATLENSURE_SUCCEEDED(PathCchRemoveFileSpec(dbghelp, ARRAYSIZE(dbghelp)));
	ATLENSURE_SUCCEEDED(PathCchAppend(dbghelp, ARRAYSIZE(dbghelp), L"dbghelp"));
	if (!LoadLibraryW(dbghelp))
	{
		die();
	}
	const HMODULE uReFS = LoadLibraryW(L"uReFS");
	if (!uReFS)
	{
		die();
	}
	if (GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", nullptr, 0) == 0)
	{
		WCHAR temp[MAX_PATH];
		ATLENSURE(GetTempPathW(ARRAYSIZE(temp), temp));
		WCHAR symsrv[ARRAYSIZE(temp) + 4 + 44];
		ATL::AtlCrtErrorCheck(wcscpy_s(symsrv, L"srv*"));
		ATL::AtlCrtErrorCheck(wcscat_s(symsrv, temp));
		ATL::AtlCrtErrorCheck(wcscat_s(symsrv, L"*https://msdl.microsoft.com/download/symbols"));
		__analysis_assume_nullterminated(symsrv);
		SetEnvironmentVariableW(L"_NT_SYMBOL_PATH", symsrv);
	}
	SymSetOptions(SymGetOptions() | SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED);
	const HANDLE CurrentProcess = GetCurrentProcess();
	if (!SymInitialize(CurrentProcess, nullptr, FALSE))
	{
		die();
	}
	WCHAR uReFS_Dll[MAX_PATH];
	if (!GetModuleFileNameW(uReFS, uReFS_Dll, ARRAYSIZE(uReFS_Dll)))
	{
		die();
	}
	if (!SymLoadModuleExW(CurrentProcess, nullptr, uReFS_Dll, nullptr, reinterpret_cast<UINT_PTR>(uReFS), 0, nullptr, 0))
	{
		die();
	}
	SYMBOL_INFO_PACKAGE symbol_info;
	symbol_info.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	symbol_info.si.MaxNameLen = 0;
	if (!SymFromName(CurrentProcess, "IsRefsFormatEnabled", &symbol_info.si))
	{
		die();
	}
#ifdef _DEBUG
	symbol_info.si.MaxNameLen = MAX_SYM_NAME;
	_ASSERT(SymFromAddr(CurrentProcess, symbol_info.si.Address, nullptr, &symbol_info.si));
	_ASSERT(strcmp(symbol_info.si.Name, "IsRefsFormatEnabled") == 0);
#endif
#if defined(_M_AMD64) || defined(_M_IX86)
	static const BYTE mov_eax_1_ret[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
	if (!WriteProcessMemory(CurrentProcess, reinterpret_cast<PVOID>(symbol_info.Address), mov_eax_1_ret, sizeof mov_eax_1_ret, nullptr))
	{
		die();
	}
	if (!FlushInstructionCache(CurrentProcess, reinterpret_cast<PVOID>(symbol_info.Address), sizeof mov_eax_1_ret))
	{
		die();
	}
#elif defined(_M_ARM64)
	static const UINT32 mov_w0_1_ret[] = { 0x52800020, 0xD65F03C0 };
	if (!WriteProcessMemory(CurrentProcess, reinterpret_cast<PVOID>(symbol_info.Address), mov_w0_1_ret, sizeof mov_w0_1_ret, nullptr))
	{
		die();
	}
	if (!FlushInstructionCache(CurrentProcess, reinterpret_cast<PVOID>(symbol_info.Address), sizeof mov_w0_1_ret))
	{
		die();
	}
#else
#error Unsupported architecture
#endif
}
struct format_options
{
	PCWSTR volume = nullptr;
	PCWSTR label = L"";
	ULONG cluster_size = 0;
	std::optional<bool> integrity;
	bool force = false;
	bool confirm = true;
};
BOOLEAN format_status;
#pragma warning(suppress : 26812)
BOOLEAN WINAPI FormatExCallback(CALLBACKCOMMAND Command, [[maybe_unused]] ULONG SubAction, PVOID ActionInfo)
{
	switch (Command)
	{
	case PROGRESS:
		__noop;
		break;
	case DONE:
		format_status = *static_cast<PBOOLEAN>(ActionInfo);
		break;
	default:
		_RPTN(_CRT_WARN, "%u:%lu\n", Command, SubAction);
	}
	return TRUE;
}
#pragma warning(suppress : 6262)
bool Format(const format_options& format_opts)
{
	const HMODULE fmifs = LoadLibraryW(L"fmifs");
	if (!fmifs)
	{
		fputs("Load fmifs.dll failed.\n", stderr);
		_CrtDbgBreak();
		ExitProcess(EXIT_FAILURE);
	}
	const PFORMATEX FormatEx = reinterpret_cast<PFORMATEX>(GetProcAddress(fmifs, "FormatEx"));
	if (!FormatEx)
	{
		fputs("Load fmifs.dll failed.\n", stderr);
		_CrtDbgBreak();
		ExitProcess(EXIT_FAILURE);
	}

	WCHAR mount_point[PATHCCH_MAX_CCH];
	ATL::AtlCrtErrorCheck(wcscpy_s(mount_point, format_opts.volume));
	ATLENSURE_SUCCEEDED(PathCchAddBackslash(mount_point, ARRAYSIZE(mount_point)));
	WCHAR volume_root[50];
	if (!GetVolumeNameForVolumeMountPointW(mount_point, volume_root, ARRAYSIZE(volume_root)))
	{
		if (GetLastError() == ERROR_NOT_A_REPARSE_POINT)
		{
			fputs("Specified path is not a mount point.\n", stderr);
			_CrtDbgBreak();
			ExitProcess(EXIT_FAILURE);
		}
		else
		{
			die();
		}
	}
	if (GetDriveTypeW(volume_root) != DRIVE_FIXED)
	{
		fputs("Specified drive is not a fixed drive\n", stderr);
		_CrtDbgBreak();
		ExitProcess(EXIT_FAILURE);
	}
	WCHAR volume_name[50];
	ATL::AtlCrtErrorCheck(wcsncpy_s(volume_name, volume_root, wcslen(volume_root) - 1));
	__analysis_assume_nullterminated(volume_name);

	ULONG junk;
	ATL::CHandle volume(CreateFileW(volume_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
	if (volume == INVALID_HANDLE_VALUE)
	{
		volume.Detach();
		die();
	}
	if (format_opts.confirm)
	{
		printf("Proceed with Format? (Y / N)");
		for (;;)
		{
			switch (toupper(_getch()))
			{
			case 'Y':
				puts(" \"Y\" pressed");
				break;
			case 'N':
				ExitProcess(EXIT_FAILURE);
			default:
				continue;
			}
			break;
		}
	}
	FSCTL_SET_INTEGRITY_INFORMATION_BUFFER set_integrity = {};
	if (format_opts.integrity)
	{
		if (*format_opts.integrity)
		{
			set_integrity.ChecksumAlgorithm = CHECKSUM_TYPE_CRC64;
		}
		else
		{
			set_integrity.ChecksumAlgorithm = CHECKSUM_TYPE_NONE;
		}
	}
	else
	{
		STORAGE_PROPERTY_QUERY storage_query = { StorageDeviceResiliencyProperty, PropertyStandardQuery };
		STORAGE_DEVICE_RESILIENCY_DESCRIPTOR storage_resiliency;
		if (DeviceIoControl(volume, IOCTL_STORAGE_QUERY_PROPERTY, &storage_query, sizeof storage_query, &storage_resiliency, sizeof storage_resiliency, &junk, nullptr) && storage_resiliency.PhysicalDiskRedundancy)
		{
			set_integrity.ChecksumAlgorithm = CHECKSUM_TYPE_CRC64;
		}
		else
		{
			set_integrity.ChecksumAlgorithm = CHECKSUM_TYPE_NONE;
		}
	}
	if (!DeviceIoControl(volume, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &junk, nullptr))
	{
		if (format_opts.force)
		{
			DeviceIoControl(volume, FSCTL_DISMOUNT_VOLUME, nullptr, 0, nullptr, 0, &junk, nullptr);
		}
		else
		{
			printf("Volume in use. Force continue? (Y / N)");
			for (;;)
			{
				switch (toupper(_getch()))
				{
				case 'Y':
					puts(" \"Y\" pressed");
					DeviceIoControl(volume, FSCTL_DISMOUNT_VOLUME, nullptr, 0, nullptr, 0, &junk, nullptr);
					break;
				case 'N':
					ExitProcess(EXIT_FAILURE);
				default:
					continue;
				}
				break;
			}
		}
	}
	volume.Close();

	FormatEx(volume_name, MEDIA_TYPE::FixedMedia, const_cast<PWSTR>(L"ReFS"), const_cast<PWSTR>(format_opts.label), TRUE, format_opts.cluster_size, FormatExCallback);
	if (!format_status)
	{
		fputs("Format failed.\n", stderr);
		_CrtDbgBreak();
		return false;
	}
	ATL::CHandle root_directory(CreateFileW(volume_root, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
	if (!DeviceIoControl(root_directory, FSCTL_SET_INTEGRITY_INFORMATION, &set_integrity, sizeof set_integrity, nullptr, 0, &junk, nullptr))
	{
		fputs("Setting integrity attribute failed.\n", stderr);
		_CrtDbgBreak();
		return false;
	}
	return true;
}
[[noreturn]]
void usage()
{
	fputs(
		"Formats a disk for use with Windows.\n"
		"\n"
		"MKREFS volume [/V:label] [/A:{4096 | 64K}] [/I:{enable | disable}] [/X]\n"
		"\n"
		"  /V:label        Specifies the volume label.\n"
		"  /X              Forces the volume to dismount first if necessary.  All opened\n"
		"                  handles to the volume would no longer be valid.\n"
		"  /A:size         Overrides the default allocation unit size.\n"
		"                  ReFS supports 4096, 64K.\n"
		"  /I:state        Specifies whether integrity should be enabled on\n"
		"                  the new volume. \"state\" is either \"enable\" or \"disable\"\n"
		"                  Integrity is enabled on storage that supports data redundancy\n"
		"                  by default.\n"
		"  /FS:            Ignore.\n"
		"  /Q              Ignore. Always performs quick format.\n",
		stderr);
	_CrtDbgBreak();
	ExitProcess(EXIT_FAILURE);
}
int __cdecl wmain(int argc, PWSTR argv[])
{
	ATLENSURE(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32));
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignedDllPolicy;
	ATLENSURE(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &SignedDllPolicy, sizeof SignedDllPolicy));
	SignedDllPolicy.MicrosoftSignedOnly = 1;
	ATLENSURE(SetProcessMitigationPolicy(ProcessSignaturePolicy, &SignedDllPolicy, sizeof SignedDllPolicy));
#ifdef _CONTROL_FLOW_GUARD
	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY CfgPolicy;
	ATLENSURE(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &CfgPolicy, sizeof CfgPolicy));
	CfgPolicy.StrictMode = 1;
	ATLENSURE(SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, &CfgPolicy, sizeof CfgPolicy));
#endif
	SetErrorMode(SEM_FAILCRITICALERRORS);
	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
	setlocale(LC_ALL, "");

	if (argc < 2)
	{
		usage();
	}

	format_options format_opts;
	for (int i = 1; i < argc; ++i)
	{
		if (argv[i][0] == '/' || argv[i][0] == '-')
		{
			if (_wcsicmp(&argv[i][1], L"A:4096") == 0 || _wcsicmp(&argv[i][1], L"A:4K") == 0)
			{
				format_opts.cluster_size = 4 * 1024;
			}
			else if (_wcsicmp(&argv[i][1], L"A:65536") == 0 || _wcsicmp(&argv[i][1], L"A:64K") == 0)
			{
				format_opts.cluster_size = 64 * 1024;
			}
			else if (_wcsnicmp(&argv[i][1], L"V:", 2) == 0)
			{
				format_opts.label = &argv[i][3];
			}
			else if (_wcsicmp(&argv[i][1], L"I:ENABLE") == 0)
			{
				format_opts.integrity = true;
			}
			else if (_wcsicmp(&argv[i][1], L"I:DISABLE") == 0)
			{
				format_opts.integrity = false;
			}
			else if (_wcsicmp(&argv[i][1], L"X") == 0)
			{
				format_opts.force = true;
			}
			else if (_wcsicmp(&argv[i][1], L"Y") == 0)
			{
				format_opts.force = true;
				format_opts.confirm = false;
			}
			else if (_wcsnicmp(&argv[i][1], L"FS:", 3) == 0)
			{
				__noop;
			}
			else if (_wcsicmp(&argv[i][1], L"Q") == 0)
			{
				__noop;
			}
		}
		else
		{
			if (format_opts.volume != nullptr)
			{
				usage();
			}
			format_opts.volume = argv[i];
		}
	}
	if (format_opts.volume == nullptr)
	{
		usage();
	}

	EnableRefsFormat();
	if (!Format(format_opts))
	{
		ExitProcess(EXIT_FAILURE);
	}
	puts("Done.");
}