//! @file
//! SPDX-License-Identifier: GPL-3.0-or-later

#include <Windows.h>
#include <filesystem>
#include <fstream>

using namespace std::literals;

#pragma bss_seg      (".zynamic")
                   char zynamic[0x0A000000];
__declspec(thread) char zynamic_thread_local_storage[0x10000];

namespace Zynamic
{

struct PE
{
  HMODULE           image;
  PIMAGE_DOS_HEADER image_dos_header;
  PIMAGE_NT_HEADERS image_nt_headers;
};

auto load(std::vector<char> pe)
{
  PE src{}, dst{};

  src.image = reinterpret_cast<HMODULE>(&pe.at(0));
  src.image_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(src.image);
  src.image_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned>(src.image) + src.image_dos_header->e_lfanew);
  dst.image = GetModuleHandleA(nullptr);
  dst.image_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dst.image);
  dst.image_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned>(dst.image) + dst.image_dos_header->e_lfanew);

  auto lpfl_old_protect = 0ul;
  auto section = IMAGE_FIRST_SECTION(src.image_nt_headers);

  for (auto i = 0; i < src.image_nt_headers->FileHeader.NumberOfSections; ++i, ++section)
  {
    if (!section || section->SizeOfRawData <= 0)
      continue;

    auto section_virtual_address = reinterpret_cast<void*>(reinterpret_cast<unsigned>(dst.image) + section->VirtualAddress);
    auto section_raw_data = reinterpret_cast<void*>(reinterpret_cast<unsigned>(src.image) + section->PointerToRawData);
    auto section_raw_data_size = (std::min)(section->SizeOfRawData, section->Misc.VirtualSize);

    VirtualProtect(section_virtual_address, section_raw_data_size, PAGE_EXECUTE_READWRITE, &lpfl_old_protect);
    memmove(section_virtual_address, section_raw_data, section_raw_data_size);
    VirtualProtect(section_virtual_address, section_raw_data_size, lpfl_old_protect, &lpfl_old_protect);
  }

  auto import_directory = &src.image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  auto import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<unsigned>(dst.image) + import_directory->VirtualAddress);

  while (import_descriptor->Name)
  {
    auto import_descriptor_name = reinterpret_cast<char*>(reinterpret_cast<unsigned>(dst.image) + import_descriptor->Name);
    auto import_descriptor_first_thunk = reinterpret_cast<unsigned*>(reinterpret_cast<unsigned>(dst.image) + import_descriptor->FirstThunk);
    auto import_descriptor_original_first_thunk = reinterpret_cast<unsigned*>(reinterpret_cast<unsigned>(dst.image) + import_descriptor->OriginalFirstThunk);

    while (*import_descriptor_original_first_thunk)
    {
      auto import_descriptor_library = LoadLibraryA(import_descriptor_name);
      auto import_descriptor_lookup_table = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<unsigned>(dst.image) + *import_descriptor_original_first_thunk);
      auto import_descriptor_address_table = static_cast<FARPROC>(nullptr);

      if (!import_descriptor_library)
      {
        MessageBox(nullptr, (std::string("The code execution cannot proceed because") + " " + import_descriptor_name + " " + "was not found. Reinstalling the program may fix this problem.").c_str(), "System Error", MB_ICONERROR);
        std::quick_exit(EXIT_FAILURE);
      }

      import_descriptor_address_table = IMAGE_SNAP_BY_ORDINAL(*import_descriptor_original_first_thunk) ? GetProcAddress(import_descriptor_library, MAKEINTRESOURCEA(IMAGE_ORDINAL(*import_descriptor_original_first_thunk))) : GetProcAddress(import_descriptor_library, &import_descriptor_lookup_table->Name[0]);
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

  reinterpret_cast<FARPROC>(src.image_nt_headers->OptionalHeader.AddressOfEntryPoint + 0x00400000)();
}

} // namespace Zynamic

auto main(int argc, char *argv[]) -> int
{
  if (argc < 2)
    return MessageBox(nullptr, "Please set the game executable path in property pages - debugging - command arguments.", "Fatal Error", MB_ICONERROR);

  auto filesystem = std::filesystem::path(argv[1]);

  SetCurrentDirectoryA(filesystem.parent_path().string().c_str());
  memset(zynamic_thread_local_storage, 0, sizeof zynamic_thread_local_storage);
  Zynamic::load(std::vector(std::istreambuf_iterator(std::ifstream(filesystem.filename(), std::ios::binary).rdbuf()), std::istreambuf_iterator<char>()));
}
