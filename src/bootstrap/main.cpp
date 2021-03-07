#define WIN32_LEAN_AND_MEAN 1

#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <unordered_map>

#include <string>

#include <cassert>

HMODULE gameModule;

HMODULE hkGetModuleHandleA( LPCSTR lpModuleName )
{
  if( lpModuleName == 0 )
  {
    return gameModule;
  }

  return GetModuleHandleA( lpModuleName );
}

std::unordered_map< std::string, void* > iatHooks
  {
    { "KERNEL32.dll`GetModuleHandleA", &hkGetModuleHandleA }
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

void* calc_section_addr( uint8_t* imageBase, const char* sectionName )
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

#pragma warning(push)
#pragma warning(disable: 4477)
#pragma warning(disable: 4313)
          printf( "[iat] %s.%i -> %llu\n", moduleName, ordinal, pFirstThunk->u1.Function );
#pragma warning(pop)
        }
        else
        {
          auto pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
            imageBase + pOriginalFirstThunk->u1.AddressOfData
          );
          auto fn = GetProcAddress( hModule, pImport->Name );


          // spaghet
          char hookName[128];
          sprintf_s( hookName, 128, "%s`%s", moduleName, pImport->Name );

          auto replacement = findIatHook( hookName );
          if( replacement )
          {
            pFirstThunk->u1.Function = reinterpret_cast<uintptr_t>(replacement);
            printf( "[iat] (hooked) %s`%s -> %llu\n", moduleName, pImport->Name, pFirstThunk->u1.Function );
          }
          else
          {
            pFirstThunk->u1.Function = reinterpret_cast<uintptr_t>(fn);
            printf( "[iat] %s`%s -> %llu\n", moduleName, pImport->Name, pFirstThunk->u1.Function );
          }
        }

        ++pOriginalFirstThunk;
        ++pFirstThunk;
      }

      ++pImportDesc;
    }
  }

  auto tls = optionalHdr->DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];
  if( tls.Size )
  {
    auto pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(
      imageBase + tls.VirtualAddress
    );
    auto pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(
      pTLS->AddressOfCallBacks
    );

    // todo: not actually sure why but there's a tls section but no entries? wat

    for( ; pCallback && *pCallback; ++pCallback )
    {
      // todo: wtf args to use here
      ( *pCallback )( imageBase, 0, nullptr );
    }
  }

  auto teb = NtCurrentTeb();
  auto tlsSection = calc_section_addr( imageBase, ".tls" );
  *( void** ) ( teb->Reserved1[ 11 ] ) = tlsSection;
  printf( "[teb] section: %p\n", tlsSection );

  if( !tlsSection )
  {
    printf( "[teb] teb machine broke\n", tlsSection );
    exit( 69420 );
  }

  // this is just a test, don't bash me for shit patching lol
  auto openprocess = reinterpret_cast<uint8_t*>(imageBase + 0x58102);
  openprocess[ 0 ] = 0x33;
  openprocess[ 1 ] = 0xC0;
  openprocess[ 2 ] = 0x90;
  openprocess[ 3 ] = 0x90;
  openprocess[ 4 ] = 0x90;
  openprocess[ 5 ] = 0x90;

  // todo: fix section protections
  for( int i = 0; i < ntHdr->FileHeader.NumberOfSections; ++i )
  {
    auto section = IMAGE_FIRST_SECTION( ntHdr ) + i;

    printf( "section: %s\n", section->Name );
  }
}

int main( int argc, char** argv )
{
  //  for( int i = 0; i < argc; ++i )
  //  {
  //    printf( "[%i] %s\n", i, argv[ i ] );
  //  }

  std::string gameFolder = "G:/SteamLibrary/steamapps/common/FINAL FANTASY XIV Online/game/";

  if( argc > 1 )
  {
    printf( "using game folder: %s\n", argv[ 1 ] );
    gameFolder = argv[ 1 ];
  }

  std::string gameExecutable = gameFolder + "ffxiv_dx11.exe";

  auto module = LoadLibrary( gameExecutable.c_str() );
  if( !module )
  {
    printf( "failed to load ffxiv_dx11.exe\n" );
    return 1;
  }
  gameModule = module;
  auto imageBase = reinterpret_cast<uint8_t*>(module);

  printf( "module base: %p\n", module );

  SetCurrentDirectory( gameFolder.c_str() );

  auto dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
  if( dosHdr->e_magic != IMAGE_DOS_SIGNATURE )
  {
    printf( "bad magic\n" );
    return 1;
  }

  fixModule( imageBase );

  using CRTStartFn = uint64_t( * )();

  auto crtStart = reinterpret_cast<CRTStartFn>(imageBase + 0x13725D4);

  printf( "CRTStart: \t%p\n", crtStart );

  crtStart();

  return 0;
}

