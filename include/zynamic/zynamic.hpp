#pragma once

#include <string>
#include <unordered_map>
#include <functional>

namespace Zynamic
{
namespace Dia
{

using  unordered_map = std::unordered_map<unsigned long, std::wstring>;
using  unordered_map_reverse = std::unordered_map<std::wstring, unsigned long>;
extern unordered_map get_src_symbol_by_address, get_dst_symbol_by_address;
extern unordered_map_reverse get_src_symbol_by_name, get_dst_symbol_by_name;

} // namespace Dia

template <typename T>
std::function<T> Forward(const wchar_t* name)
{
  return std::function<T>(reinterpret_cast<T*>(Dia::get_src_symbol_by_name.at(name)));
}

} // namespace Zynamic
