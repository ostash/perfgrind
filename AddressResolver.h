#ifndef ADDRESSRESOLVER_H
#define ADDRESSRESOLVER_H

#include "Profile.h"

#include <utility>
#include <stdint.h>

class AddressResolverPrivate;

class AddressResolver
{
public:
  AddressResolver(Profile::DetailLevel details, const char* fileName, uint64_t objectSize);
  ~AddressResolver();

  Address baseAddress() const;
  bool resolve(Address value, Address loadBase, Range& symbolRange, std::string& symbolName) const;
  std::pair<const char*, size_t> getSourcePosition(Address value, Address loadBase) const;

private:
  AddressResolver(const AddressResolver&);
  AddressResolver& operator=(const AddressResolver&);
  AddressResolverPrivate* d;
};

#endif // ADDRESSRESOLVER_H
