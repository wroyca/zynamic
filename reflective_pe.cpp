//! @file
//! SPDX-License-Identifier: GPL-3.0-or-later
//! code based on https://github.com/momo5502/open-iw5/blob/master/src/loader/loader.cpp

#include <Windows.h>
#include <atlstr.h>
#include <vector>
#include <fstream>

#pragma bss_seg      (".reflective_pe")
                   char reflective_pe[0x0A000000];
__declspec(thread) char reflective_pe_thread_local_storage[0x10000];

namespace ReflectivePE
{

#ifdef PATCHES
namespace Patches { void main(); }
#endif

struct PE
{
  HMODULE           image;
  PIMAGE_DOS_HEADER image_dos_header;
  PIMAGE_NT_HEADERS image_nt_headers;
};

void load(std::vector<char> pe)
{
  PE src, dst;

  src.image = reinterpret_cast<HMODULE>(&pe.at(0));
  src.image_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(src.image);
  src.image_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned>(src.image) + src.image_dos_header->e_lfanew);
  dst.image = GetModuleHandleA(NULL);
  dst.image_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dst.image);
  dst.image_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned>(dst.image) + dst.image_dos_header->e_lfanew);

  unsigned long lpfl_old_protect = 0ul;
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(src.image_nt_headers);

  for (int i = 0; i < src.image_nt_headers->FileHeader.NumberOfSections; ++i, ++section)
  {
    if (!section || section->SizeOfRawData <= 0)
      continue;

    void *section_virtual_address = reinterpret_cast<void*>(reinterpret_cast<unsigned>(dst.image) + section->VirtualAddress);
    void *section_raw_data = reinterpret_cast<void*>(reinterpret_cast<unsigned>(src.image) + section->PointerToRawData);
    unsigned long section_raw_data_size = (std::min)(section->SizeOfRawData, section->Misc.VirtualSize);

    VirtualProtect(section_virtual_address, section_raw_data_size, PAGE_EXECUTE_READWRITE, &lpfl_old_protect);
    memmove(section_virtual_address, section_raw_data, section_raw_data_size);
    VirtualProtect(section_virtual_address, section_raw_data_size, lpfl_old_protect, &lpfl_old_protect);
  }

  PIMAGE_DATA_DIRECTORY import_directory = &src.image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  PIMAGE_IMPORT_DESCRIPTOR import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<unsigned>(dst.image) + import_directory->VirtualAddress);

  while (import_descriptor->Name)
  {
    char *import_descriptor_name = reinterpret_cast<char*>(reinterpret_cast<unsigned>(dst.image) + import_descriptor->Name);
    unsigned *import_descriptor_first_thunk = reinterpret_cast<unsigned*>(reinterpret_cast<unsigned>(dst.image) + import_descriptor->FirstThunk);
    unsigned *import_descriptor_original_first_thunk = reinterpret_cast<unsigned*>(reinterpret_cast<unsigned>(dst.image) + import_descriptor->OriginalFirstThunk);

    while (*import_descriptor_original_first_thunk)
    {
      HMODULE import_descriptor_library = LoadLibraryA(import_descriptor_name);
      PIMAGE_IMPORT_BY_NAME import_descriptor_lookup_table = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<unsigned>(dst.image) + *import_descriptor_original_first_thunk);
      FARPROC import_descriptor_address_table;

      if (!import_descriptor_library)
      {
        MessageBox(NULL, std::string("The code execution cannot proceed because").append(" ").append(import_descriptor_name).append(" ").append("was not found. Reinstalling the program may fix this problem.").c_str(), "System Error", MB_ICONERROR);
        _exit(EXIT_FAILURE);
      }

      import_descriptor_address_table = IMAGE_SNAP_BY_ORDINAL(*import_descriptor_original_first_thunk) ? GetProcAddress(import_descriptor_library, MAKEINTRESOURCEA(IMAGE_ORDINAL(*import_descriptor_original_first_thunk))) : GetProcAddress(import_descriptor_library, reinterpret_cast<LPCSTR>(&import_descriptor_lookup_table->Name[0]));
     *import_descriptor_first_thunk = reinterpret_cast<unsigned>(import_descriptor_address_table);
      import_descriptor_first_thunk++;
      import_descriptor_original_first_thunk++;
    }
    import_descriptor++;
  }

  VirtualProtect(dst.image_nt_headers, 0x1000, PAGE_EXECUTE_READWRITE, &lpfl_old_protect);
  dst.image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = src.image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  memmove(dst.image_nt_headers, src.image_nt_headers, sizeof(IMAGE_NT_HEADERS) + dst.image_nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
  VirtualProtect(dst.image_nt_headers, 0x1000, lpfl_old_protect, &lpfl_old_protect);

#ifdef PATCHES
  Patches::main();
#endif

  reinterpret_cast<FARPROC>(src.image_nt_headers->OptionalHeader.AddressOfEntryPoint + 0x00400000)();
}

} // namespace ReflectivePE

int main(int argc, char* argv[])
{
  if (argc < 2)
    return 1;

  CString fs_relative = argv[1];
  PathRemoveFileSpec(fs_relative.GetBuffer(0));
  fs_relative.ReleaseBuffer(-1);

  SetCurrentDirectory(fs_relative); // NOTE: Not foolproof. Some PEs try to read files using an incorrect Cwd independently.
  memset(reflective_pe_thread_local_storage, 0, sizeof reflective_pe_thread_local_storage);
  ReflectivePE::load(std::vector<char>(std::istreambuf_iterator<char>(std::ifstream(argv[1], std::ios::binary).rdbuf()), std::istreambuf_iterator<char>()));
}
