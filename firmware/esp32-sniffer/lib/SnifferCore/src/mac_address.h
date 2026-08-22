#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace defense_sniffer {

inline int hexNibble(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  return -1;
}

inline bool parseMacAddress(const char* text, uint8_t output[6]) {
  if (text == nullptr || output == nullptr) {
    return false;
  }
  if (std::strlen(text) != 17) {
    return false;
  }
  for (size_t index = 0; index < 6; ++index) {
    const int high = hexNibble(text[index * 3]);
    const int low = hexNibble(text[index * 3 + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    output[index] = static_cast<uint8_t>((high << 4) | low);
    if (index < 5 && text[index * 3 + 2] != ':') {
      return false;
    }
  }
  return (output[0] & 0x01U) == 0;
}

}  // namespace defense_sniffer
