//! SPDX-License-Identifier: GPL-3.0-or-later

#include <Windows.h>
#include <comdef.h>
#include <comutil.h>
#include <atlcomcli.h>

#include <dia2.h>
#include <diacreate.h>
#include <Zydis/Zydis.h>

#include <fstream>
#include <filesystem>
#include <optional>

#include <zynamic/zynamic.hpp>

using namespace std::literals;

#pragma bss_seg      (".zynamic")
                   char zynamic[0x0A000000 * 2]; // 0x0A000000 * 2 may not be enough in the future.
__declspec(thread) char zynamic_thread_local_storage[0x10000];

namespace Zynamic
{
namespace Dia
{

template<class T>
using as_ref = std::optional<std::reference_wrapper<T>>;

// Linear search is too slow for Zynamic.

unordered_map get_src_symbol_by_address, get_dst_symbol_by_address;
unordered_map_reverse get_src_symbol_by_name, get_dst_symbol_by_name;

namespace Zydis
{

#define OPCODE_CALL 0xE8

ZydisFormatterFunc ZydisDecodeAbsoluteHook;
ZydisFormatterFunc ZydisDecodeImmediateHook;
ZydisFormatterFunc ZydisDecodeRegisterHook;
ZyanU64            ZydisRuntimeAddress;

enum class Operand
{
  Absolute,
  Immediate,
  Register,
};

//!
//! @brief Swap the address of a call procedure.
//!
//! @param source The calling procedure address in the source binary.
//! @param destination The calling procedure address in the loaded binary.
//!
auto ZydisBind(const unsigned long source, unsigned char* destination) -> void
{
  auto page_protection = 0ul;
  auto opcode = reinterpret_cast<unsigned char*>(source);

  if (*opcode != OPCODE_CALL)
    return;

  VirtualProtect(reinterpret_cast<void*>(source), 5, PAGE_EXECUTE_READWRITE, &page_protection);
  reinterpret_cast<unsigned long*>(opcode + 1)[0] = reinterpret_cast<unsigned long>(destination) - reinterpret_cast<unsigned long>(opcode + 5);
  VirtualProtect(reinterpret_cast<void*>(source), 5, page_protection, &page_protection);
  FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(source), 5);
}

//!
//! @brief Swap the address of a global data.
//!
//! @param source The global data address in the source binary.
//! @param destination The global data address in the loaded binary.
//! @param zydis_extended_instruction_pointer The extended instruction pointer address during the decoding procedure.
//!
auto ZydisBind(const unsigned long source, unsigned long destination, const unsigned long zydis_extended_instruction_pointer)
{
  auto ZydisBind = [](const unsigned long source, unsigned char* destination, const unsigned long length)
  {
    auto page_protection = 0ul;
    VirtualProtect(reinterpret_cast<void*>(source), length, PAGE_EXECUTE_READWRITE, &page_protection);
    for (auto i = 0ul; i < 4; i++) *reinterpret_cast<volatile unsigned char*>(source + i) = *destination++;
    VirtualProtect(reinterpret_cast<void*>(source), length, page_protection, &page_protection);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(source), length);
  };

  // Increment Zydis EIP until the bytes of the next instructions to
  // be decoded match our global address.
  for (auto i = 0; i < 6; i++)
  {
    if (*reinterpret_cast<unsigned long*>(zydis_extended_instruction_pointer + i) == source)
      return ZydisBind(zydis_extended_instruction_pointer + i, reinterpret_cast<unsigned char*>(&destination), 4);
  }
}

//!
//! @brief Parse the absolute operand during the decoding procedure
//!
//! @remark Only ZYDIS_MNEMONIC_CALL is processed for the moment. Others will come later.
//!
auto ZydisDecodeAbsolute(const ZydisFormatter* formatter, ZydisFormatterBuffer* buffer, ZydisFormatterContext* context) -> ZyanStatus
{
  ZyanU64 address;
  ZYAN_CHECK(ZydisCalcAbsoluteAddress(context->instruction, context->operand, context->runtime_address, &address));

  if (context->instruction->mnemonic != ZYDIS_MNEMONIC_CALL)
    return ZydisDecodeAbsoluteHook(formatter, buffer, context);

  if (!get_src_symbol_by_address.count(address))
    return ZydisDecodeAbsoluteHook(formatter, buffer, context);

  if (const auto& name = get_src_symbol_by_address.at(address); get_dst_symbol_by_name.count(name))
    ZydisBind(static_cast<unsigned long>(ZydisRuntimeAddress), reinterpret_cast<unsigned char*>(get_dst_symbol_by_name.at(name)));

  return ZydisDecodeAbsoluteHook(formatter, buffer, context);
}

//!
//! @brief Parse the immediate operand during the decoding procedure
//!
//! @warning This is in progress and is not yet available.
//!
auto ZydisDecodeImmediate(const ZydisFormatter* formatter, ZydisFormatterBuffer* buffer, ZydisFormatterContext* context) -> ZyanStatus
{
  return ZydisDecodeImmediateHook(formatter, buffer, context);
}

//!
//! @brief Parse the register operand during the decoding procedure
//!
//! @warning This is in progress and is not yet available.
//!
auto ZydisDecodeRegister(const ZydisFormatter* formatter, ZydisFormatterBuffer* buffer, ZydisFormatterContext* context) -> ZyanStatus
{
  return ZydisDecodeRegisterHook(formatter, buffer, context);
}

//!
//! @brief Decodes the received symbol.
//!
//! @param address The symbol location.
//! @param length  The symbol length.
//! @param operand The operand to be parsed from the symbol during the decoding procedure.
//!
auto ZydisDecode(ZyanU64 address, ZyanUSize length, Operand operand)
{
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

  ZydisFormatter formatter;
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

  switch (operand)
  {
  case Operand::Absolute:
    ZydisDecodeAbsoluteHook = &ZydisDecodeAbsolute;
    ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS, (const void**)&ZydisDecodeAbsoluteHook);
    break;
  case Operand::Immediate:
    ZydisDecodeImmediateHook = &ZydisDecodeImmediate;
    ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS, (const void**)&ZydisDecodeImmediateHook);
    break;
  case Operand::Register:
    ZydisDecodeRegisterHook = &ZydisDecodeRegister;
    ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS, (const void**)&ZydisDecodeRegisterHook);
    break;
  }

  ZyanU8* data = reinterpret_cast<unsigned char*>(address);
  ZyanU64 runtime_address = address;
  ZyanUSize offset = 0;
  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

  while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, length - offset, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
  {
    char buffer[256];
    ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);
    offset += instruction.length;
    runtime_address += instruction.length;
    ZydisRuntimeAddress = runtime_address;
  }
}

} // namespace Zyids

struct PDB
{
  std::wstring            dia;
  CComPtr<IDiaDataSource> dia_data_source;
  CComPtr<IDiaSession>    dia_session;
  CComPtr<IDiaSymbol>     dia_symbol;
};

//!
//! @brief Cache the symbols from the PDBs and forward them to Zydis decoder.
//!
auto load()
{
  PDB src{}, dst{};

  src.dia = BIN + L".pdb"s;
  dst.dia = DST + L".pdb"s;

  auto get_global_scope = [](PDB& pdb)
  {
    try
    {
      if (const auto hr = NoRegCoCreate(DIA, CLSID_DiaSource, IID_IDiaDataSource, reinterpret_cast<void**>(&pdb.dia_data_source)); FAILED(hr))
        _com_issue_error(hr);
      if (const auto hr = pdb.dia_data_source->loadDataFromPdb(pdb.dia.c_str()); FAILED(hr))
        _com_issue_error(hr);
      if (const auto hr = pdb.dia_data_source->openSession(&pdb.dia_session); FAILED(hr))
        _com_issue_error(hr);
      if (const auto hr = pdb.dia_session->get_globalScope(&pdb.dia_symbol); FAILED(hr))
        _com_issue_error(hr);
    }
    catch (const _com_error& e)
    {
      MessageBoxA(nullptr, e.ErrorMessage(), "Fatal Error", MB_ICONERROR);
      std::quick_exit(EXIT_FAILURE);
    }
  };

  //
  // Dia lookup is not consistent, so we cache the symbols
  // information in a map to avoid potential problems.
  //

  auto map_global_scope = [](const PDB& pdb, const enum SymTagEnum sym_tag, as_ref<unordered_map> rhs = std::nullopt, as_ref<unordered_map_reverse> lhs = std::nullopt)
  {
    CComPtr<IDiaSymbol> children;
    CComPtr<IDiaEnumSymbols> enum_children;

    pdb.dia_symbol->findChildren(sym_tag, nullptr, nsNone, &enum_children);
    unsigned long celt = 0;

    while (SUCCEEDED(enum_children->Next(1, &children, &celt)) && celt == 1)
    {
      wchar_t* name = L"";
      unsigned long rva = 0;
      unsigned long long length = 0;

      children->get_name(&name);
      children->get_relativeVirtualAddress(&rva);
      children->get_length(&length);

      //
      // It is possible that get_name returns an empty string or a
      // reserved symbol. So we create a special set of rules to
      // filter the problematic ones.
      //
      auto keywords = { L"std::"s, L"atexit"s, L"operator"s, L"__"s, L"~"s };

      auto reserved = std::any_of(std::begin(keywords), std::end(keywords), [&](const std::wstring& keyword)
      {
        return std::wstring(name).find(keyword) != std::string::npos;
      });

      if (wcscmp(name, L"") != 0 && !reserved && name[0] != '_')
      {
        #ifdef    _ZYDEBUG
        OutputDebugStringW((std::wstring(name) + L"\n"s).c_str());
        #endif // _ZYDEBUG
        rva += 0x00400000;
        rhs.has_value() ? rhs.value().get().insert({ rva, name }) :
        lhs.has_value() ? lhs.value().get().insert({ name, rva }) :
        ZydisDecode(rva, static_cast<ZyanUSize>(length), Zydis::Operand::Absolute);
        SysFreeString(name);
      }
      children.Release();
    }
    enum_children.Release();
  };

  // Second pass on the lambda with Zydis
  auto dec_global_scope = map_global_scope;

  #ifndef FAKE_PDB
  #define SymTagPublicSymbol SymTagFunction // FakePDB currently only supports SymTagPublicSymbol.
  #endif

  get_global_scope(src);
  get_global_scope(dst);
  map_global_scope(src, SymTagPublicSymbol, get_src_symbol_by_address);
  map_global_scope(dst, SymTagFunction, get_dst_symbol_by_address);
  map_global_scope(src, SymTagPublicSymbol, std::nullopt, get_src_symbol_by_name);
  map_global_scope(dst, SymTagFunction, std::nullopt, get_dst_symbol_by_name);
  dec_global_scope(src, SymTagPublicSymbol);
}

} // namespace Dia

struct PE
{
  HMODULE           image;
  PIMAGE_DOS_HEADER image_dos_header;
  PIMAGE_NT_HEADERS image_nt_headers;
};

//!
//! @brief Mimics how the Windows Loader maps a PE into memory.
//!
//! Each section and imports are mapped into memory at a relative
//! address that is dictated by the PE header.
//!
auto load(std::vector<char> pe)
{
  PE src{}, dst{};

  src.image = reinterpret_cast<HMODULE>(&pe.at(0));
  src.image_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(src.image);
  src.image_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned>(src.image) + src.image_dos_header->e_lfanew);
  dst.image = GetModuleHandleA(nullptr);
  dst.image_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dst.image);
  dst.image_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned>(dst.image) + dst.image_dos_header->e_lfanew);

  auto section = IMAGE_FIRST_SECTION(src.image_nt_headers);

  for (auto i = 0; i < src.image_nt_headers->FileHeader.NumberOfSections; ++i, ++section)
  {
    if (!section || section->SizeOfRawData <= 0)
      continue;

    auto section_virtual_address = reinterpret_cast<void*>(reinterpret_cast<unsigned>(dst.image) + section->VirtualAddress);
    auto section_raw_data = reinterpret_cast<void*>(reinterpret_cast<unsigned>(src.image) + section->PointerToRawData);
    auto section_raw_data_size = (std::min)(section->SizeOfRawData, section->Misc.VirtualSize);
    auto section_page_protection = 0ul;

    VirtualProtect(section_virtual_address, section_raw_data_size, PAGE_EXECUTE_READWRITE, &section_page_protection);
    memmove(section_virtual_address, section_raw_data, section_raw_data_size);
    VirtualProtect(section_virtual_address, section_raw_data_size, section_page_protection, &section_page_protection);
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
      auto import_descriptor_address_table = IMAGE_SNAP_BY_ORDINAL(*import_descriptor_original_first_thunk) ? GetProcAddress(import_descriptor_library, MAKEINTRESOURCEA(IMAGE_ORDINAL(*import_descriptor_original_first_thunk))) : GetProcAddress(import_descriptor_library, &import_descriptor_lookup_table->Name[0]);

      if (!import_descriptor_library)
      {
        MessageBoxA(nullptr, ("The code execution cannot proceed because "s + import_descriptor_name + " was not found."s).c_str(), "Fatal Error", MB_ICONERROR);
        std::quick_exit(EXIT_FAILURE);
      }

     *import_descriptor_first_thunk = reinterpret_cast<unsigned>(import_descriptor_address_table);
      import_descriptor_first_thunk++;
      import_descriptor_original_first_thunk++;
    }
    import_descriptor++;
  }

  auto image_nt_headers_page_protection = 0ul;
  VirtualProtect(dst.image_nt_headers, 0x1000, PAGE_EXECUTE_READWRITE, &image_nt_headers_page_protection);
  dst.image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = src.image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  memmove(dst.image_nt_headers, src.image_nt_headers, sizeof(IMAGE_NT_HEADERS) + dst.image_nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
  VirtualProtect(dst.image_nt_headers, 0x1000, image_nt_headers_page_protection, &image_nt_headers_page_protection);

  Dia::load();
  reinterpret_cast<FARPROC>(src.image_nt_headers->OptionalHeader.AddressOfEntryPoint + 0x00400000)();
}

} // namespace Zynamic

//!
//! @brief Provides a version of main() which performs some initialization before calling the loaded binary entry point.
//!
auto main() -> int
{
  memset(zynamic_thread_local_storage, 0, sizeof zynamic_thread_local_storage);
  Zynamic::load(std::vector(std::istreambuf_iterator(std::ifstream(BIN + L".exe"s, std::ios::binary).rdbuf()), std::istreambuf_iterator<char>()));
}
