#ifndef ADDRESSRESOLVER_H
#define ADDRESSRESOLVER_H

#include "Profile.h"

#include <utility>
#include <stdint.h>

class AddressResolverPrivate;

class AddressResolver
{
public:
  AddressResolver(ProfileDetails details, const char* fileName);
  ~AddressResolver();

  /**
   * @brief Resolves address to the symbol
   * @note Returned symbol name can be empty, use AddressResolver::constructSymbolNameFromAddress() to construct fake
   * name
   * @note Resolution failure is reported by returning empty range
   * @param address An address to resolve in ELF space
   * @return Symbol name and range of the addresses which is covered by the symbol.
   */
  std::pair<std::string, Range> resolve(Address address) const;
  std::pair<const char*, size_t> getSourcePosition(Address address) const;

  bool usesAbsoluteAddresses() const { return usesAbsoluteAddresses_; }

  static std::string constructSymbolNameFromAddress(Address address);

private:
  AddressResolver(const AddressResolver&);
  AddressResolver& operator=(const AddressResolver&);
  AddressResolverPrivate* d;

  bool usesAbsoluteAddresses_ = false;
};

#endif // ADDRESSRESOLVER_H
