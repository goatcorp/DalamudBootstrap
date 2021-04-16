#include <cstdint>

// yolo
#pragma section(".fuck", read, write, execute)
const uint32_t shitSize = 1024 * 1024 * 69; // 69ish mb
__declspec(allocate(".fuck")) uint8_t clientBinary[shitSize];
#pragma comment(linker, "/merge:.fuck=.text")

#define WIN32_LEAN_AND_MEAN 1

#include <windows.h>
#include <winternl.h>
#include <processthreadsapi.h>

#include <unordered_map>

#include <string>

#include <cassert>

#include <cstdlib>
#include <atomic>

#include "Logger.h"


HMODULE gameModule;
uintptr_t gameTlsSection;

HMODULE hkGetModuleHandleA( LPCSTR lpModuleName )
{
  if( lpModuleName == 0 )
  {
    return gameModule;
  }

  return GetModuleHandleA( lpModuleName );
}

HANDLE hkCreateFileW(
  LPCWSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile
)
{
  char path[MAX_PATH];
  size_t written = 0;
  wcstombs_s( &written, path, lpFileName, MAX_PATH );


  auto handle = CreateFileW(
    lpFileName,
    dwDesiredAccess,
    dwShareMode,
    lpSecurityAttributes,
    dwCreationDisposition,
    dwFlagsAndAttributes,
    hTemplateFile
  );

  if( handle == INVALID_HANDLE_VALUE )
  {
    auto err = GetLastError();
    Logger::debug( "[CreateFileW] INVALID_HANDLE_VALUE, err: {}", err );

    return handle;
  }

  if( handle )
  {
    char fullPath[MAX_PATH];
    GetFinalPathNameByHandle( handle, fullPath, MAX_PATH, VOLUME_NAME_DOS );

    Logger::debug( "[CreateFileW] {}", fullPath );
  }

  return handle;
}

typedef struct _THREAD_BASIC_INFORMATION
{
  NTSTATUS ExitStatus;
  PVOID TebBaseAddress;
  CLIENT_ID ClientId;
  KAFFINITY AffinityMask;
  KPRIORITY Priority;
  KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

HANDLE hkCreateThread(
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  __drv_aliasesMem LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPDWORD lpThreadId
)
{
  auto thread = CreateThread(
    lpThreadAttributes,
    dwStackSize,
    lpStartAddress,
    lpParameter,
    dwCreationFlags | CREATE_SUSPENDED,
    lpThreadId
  );

  if( thread == NULL )
  {
    return thread;
  }

  using NtQueryInformationThreadFn = int ( * )(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
  );

  static NtQueryInformationThreadFn queryInformationThread = nullptr;
  if( queryInformationThread == nullptr )
  {
    auto ntdll = GetModuleHandle( "ntdll.dll" );
    queryInformationThread = reinterpret_cast< NtQueryInformationThreadFn >(
      GetProcAddress( ntdll, "NtQueryInformationThread" )
    );
  }

  static std::atomic< uint32_t > tlsThreadIndex = 0;

  THREAD_BASIC_INFORMATION tbi = { 0 };

  queryInformationThread(
    thread,
    static_cast<THREADINFOCLASS>(0),
    &tbi,
    sizeof( tbi ),
    nullptr
  );

  auto teb = reinterpret_cast< TEB* >( tbi.TebBaseAddress );
  auto tebAddr = gameTlsSection + ( ++tlsThreadIndex * 0x2000 );
  teb->Reserved1[ 11 ] = *reinterpret_cast<void**>(&tebAddr);

  Logger::debug(
    "created thread={:p} _TEB->ThreadLocalStoragePointer={:p} .tls+{:p}",
    thread,
    reinterpret_cast< void* >( teb->Reserved1[ 11 ] ),
    reinterpret_cast< void* >( tebAddr - gameTlsSection )
  );

  ResumeThread( thread );

  return thread;
}

DWORD hkGetModuleFileNameW(
  HMODULE hModule,
  LPWSTR lpFilename,
  DWORD nSize
)
{
  if( hModule == NULL )
  {
    return GetModuleFileNameW( gameModule, lpFilename, nSize );
  }

  return GetModuleFileNameW( hModule, lpFilename, nSize );
}

DWORD hkGetModuleFileNameA(
  HMODULE hModule,
  LPSTR lpFilename,
  DWORD nSize
)
{
  if( hModule == NULL )
  {
    return GetModuleFileNameA( gameModule, lpFilename, nSize );
  }

  return GetModuleFileNameA( hModule, lpFilename, nSize );
}

HANDLE hkOpenProcess(
  DWORD dwDesiredAccess,
  BOOL bInheritHandle,
  DWORD dwProcessId
)
{
  // todo: no idea if this actually breaks anything we care about but lol...
  return 0;
}

std::unordered_map< std::string, void* > iatHooks
  {
    { "KERNEL32.dll`GetModuleHandleA",   &hkGetModuleHandleA },
    { "KERNEL32.dll`CreateFileW",        &hkCreateFileW },
    { "KERNEL32.dll`GetModuleFileNameW", &hkGetModuleFileNameW },
    { "KERNEL32.dll`GetModuleFileNameA", &hkGetModuleFileNameA },
    { "KERNEL32.dll`OpenProcess",        &hkOpenProcess },
    { "KERNEL32.dll`CreateThread",       &hkCreateThread },
  };

void* findIatHook( const std::string& name )
{
  auto needle = iatHooks.find( name );
  if( needle == iatHooks.end() )
  {
    return nullptr;
  }

  return needle->second;
}

HMODULE findModule( char* moduleName )
{
  //  auto existingModule = GetModuleHandleA( moduleName );
  //  if( existingModule )
  //  {
  //    return existingModule;
  //  }

  return LoadLibraryA( moduleName );
}

uint8_t* getEntryPointAddr( uint8_t* imageBase )
{
  auto dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
  auto ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + dosHdr->e_lfanew);

  return imageBase + ntHdr->OptionalHeader.AddressOfEntryPoint;
}

void* getSectionBase( uint8_t* imageBase, const char* sectionName )
{
  auto dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
  auto ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + dosHdr->e_lfanew);
  auto fileHdr = &ntHdr->FileHeader;

  for( auto i = 0; i < fileHdr->NumberOfSections; i++ )
  {
    auto sectionHdr = reinterpret_cast<PIMAGE_SECTION_HEADER>(
      ( uint8_t* ) ntHdr + sizeof( IMAGE_NT_HEADERS ) + i * sizeof( IMAGE_SECTION_HEADER )
    );

    if( !strcmp( sectionName, reinterpret_cast<const char*>(sectionHdr->Name) ) )
    {
      return imageBase + sectionHdr->VirtualAddress;
    }
  }

  return nullptr; // if we get here we're fucked so yolo
}

void fixModule( uint8_t* imageBase )
{
  assert( imageBase );

  auto dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
  auto ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + dosHdr->e_lfanew);
  auto optionalHdr = &ntHdr->OptionalHeader;

  // don't need to reloc because we're loadlibrarying it
  // but validate that it's not fucked just in case
  auto relocDelta = imageBase - ntHdr->OptionalHeader.ImageBase;
  assert( relocDelta == 0 );

  DWORD oldProtect;
  // todo: restore this shit
  if( !VirtualProtect( imageBase, optionalHdr->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect ) )
  {
    // wtf?
  }

  auto importDir = optionalHdr->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
  if( importDir.Size )
  {
    auto pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
      imageBase + importDir.VirtualAddress
    );

    while( pImportDesc->Characteristics )
    {
      auto moduleName = reinterpret_cast<char*>(imageBase + pImportDesc->Name);
      auto hModule = findModule( moduleName );

      auto pOriginalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
        imageBase + pImportDesc->OriginalFirstThunk
      );
      auto pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
        imageBase + pImportDesc->FirstThunk
      );

      if( !pOriginalFirstThunk )
        pOriginalFirstThunk = pFirstThunk;

      while( pOriginalFirstThunk->u1.AddressOfData )
      {
        if( pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
        {
          auto ordinal = MAKEINTRESOURCEA( pOriginalFirstThunk->u1.Ordinal );
          auto fn = GetProcAddress( hModule, ordinal );
          pFirstThunk->u1.Function = reinterpret_cast<uintptr_t>(fn);

          Logger::debug( "[iat] {}.{} -> {:x}", moduleName, reinterpret_cast< uint8_t >( ordinal ),
                         pFirstThunk->u1.Function );
        }
        else
        {
          auto pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
            imageBase + pOriginalFirstThunk->u1.AddressOfData
          );
          auto fn = GetProcAddress( hModule, pImport->Name );


          // spaghet
          auto hookName = fmt::format( "{}`{}", moduleName, pImport->Name );

          auto replacement = findIatHook( hookName );
          if( replacement )
          {
            pFirstThunk->u1.Function = reinterpret_cast<uintptr_t>(replacement);
            Logger::info( "[iat] (hooked) {}`{} -> {:x}", moduleName, pImport->Name, pFirstThunk->u1.Function );
          }
          else
          {
            pFirstThunk->u1.Function = reinterpret_cast<uintptr_t>(fn);
            Logger::debug( "[iat] {}`{} -> {:x}", moduleName, pImport->Name, pFirstThunk->u1.Function );
          }
        }

        ++pOriginalFirstThunk;
        ++pFirstThunk;
      }

      ++pImportDesc;
    }
  }

  auto teb = NtCurrentTeb();
  auto tlsSection = getSectionBase( imageBase, ".tls" );
  gameTlsSection = reinterpret_cast< uintptr_t >( tlsSection );
  *( void** ) ( teb->Reserved1[ 11 ] ) = tlsSection;
  Logger::debug( "[teb] section: {}", tlsSection );

  if( !tlsSection )
  {
    Logger::debug( "[teb] teb machine broke" );
    exit( 69420 );
  }

  // todo: fix section protections
  for( int i = 0; i < ntHdr->FileHeader.NumberOfSections; ++i )
  {
    auto section = IMAGE_FIRST_SECTION( ntHdr ) + i;

    Logger::debug( "section: {}", section->Name );
  }
}

int main( int argc, char** argv )
{
  Logger::init( "logs" );

  //  for( int i = 0; i < argc; ++i )
  //  {
  //    printf( "[%i] %s\n", i, argv[ i ] );
  //  }

  std::string gameFolder = "G:/SteamLibrary/steamapps/common/FINAL FANTASY XIV Online/game/";

  if( argc > 1 )
  {
    Logger::info( "using game folder: {}", argv[ 1 ] );
    gameFolder = argv[ 1 ];
  }

  std::string gameExecutable = gameFolder + "ffxiv_dx11.exe";

  auto module = LoadLibrary( gameExecutable.c_str() );
  if( !module )
  {
    Logger::critical( "failed to load ffxiv_dx11.exe" );
    return 1;
  }
  gameModule = module;
  auto imageBase = reinterpret_cast<uint8_t*>(module);

  Logger::debug( "module base: {}", reinterpret_cast< void* >( module ) );

  SetCurrentDirectory( gameFolder.c_str() );

  auto dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
  if( dosHdr->e_magic != IMAGE_DOS_SIGNATURE )
  {
    Logger::critical( "bad magic" );
    return 1;
  }

  fixModule( imageBase );

  using CRTStartFn = uint64_t( * )();

  auto entryPoint = reinterpret_cast<CRTStartFn>( getEntryPointAddr( imageBase ) );

  Logger::debug( "entrypoint: {}", reinterpret_cast< void* >( entryPoint ) );

  entryPoint();

  return 0;
}

