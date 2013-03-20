#ifndef ADDRESSRESOLVER_H
#define ADDRESSRESOLVER_H

#include "Profile.h"
#include <stdint.h>

class AddressResolverPrivate;

class AddressResolver
{
public:
  AddressResolver(const char* fileName, uint64_t objectSize);
  ~AddressResolver();

  void resolve(EntryStorage::const_iterator first, EntryStorage::const_iterator last, uint64_t loadBase,
               SymbolStorage& symbols);

private:
  AddressResolver(const AddressResolver&);
  AddressResolver& operator=(const AddressResolver&);
  AddressResolverPrivate* d;
};

#endif // ADDRESSRESOLVER_H
