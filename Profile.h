#ifndef PROFILE_H
#define PROFILE_H

#include <istream>
#include <map>
#include <stdint.h>

typedef uint64_t Address;
typedef uint64_t Count;
typedef uint64_t Size;

struct Range
{
  Range() {}
  Range(uint64_t _start, uint64_t _end)
    : start(_start)
    , end(_end)
  {}
  explicit Range(uint64_t value)
    : start(value)
    , end(value + 1)
  {}
  bool operator<(const Range& rhs) const
  {
    return end <= rhs.start;
  }

  uint64_t start;
  uint64_t end;
};

class SymbolData
{
public:
  const std::string& name() const { return name_; }
  const std::string& sourceFile() const { return *sourceFile_; }
  size_t sourceLine() const { return sourceLine_; }

private:
  friend class MemoryObjectDataPrivate;

  SymbolData();

  std::string name_;
  const std::string* sourceFile_;
  size_t sourceLine_;
};

typedef std::map<Range, SymbolData*> SymbolStorage;
typedef SymbolStorage::value_type Symbol;

union BranchTo
{
  BranchTo(Address value)
    : address(value)
  {}
  BranchTo(const Symbol* value)
  {
    // Here is strong assumption that sizeof(Address) >= sizeof(Symbol*)
    address = 0;
    symbol = value;
  }
  Address address;
  const Symbol* symbol;
  bool operator<(const BranchTo& other) const { return address < other.address; }
};

typedef std::map<BranchTo, Count> BranchStorage;
typedef BranchStorage::value_type Branch;

class EntryData
{
public:
  Count count() const { return count_; }
  const BranchStorage& branches() const { return branches_; }
  const std::string& sourceFile() const { return *sourceFile_; }
  size_t sourceLine() const { return sourceLine_; }

private:
  friend class MemoryObjectDataPrivate;

  explicit EntryData(Count count);

  Count count_;
  BranchStorage branches_;
  const std::string* sourceFile_;
  size_t sourceLine_;
};

typedef std::map<Address, EntryData*> EntryStorage;
typedef EntryStorage::value_type Entry;

class MemoryObjectDataPrivate;
class MemoryObjectData
{
public:
  Address baseAddress() const;
  const std::string& fileName() const;
  const EntryStorage& entries() const;
  const SymbolStorage& symbols() const;
private:
  friend class ProfilePrivate;
  friend class MemoryObjectDataPrivate;
  MemoryObjectData(const MemoryObjectData&);
  MemoryObjectData& operator=(const MemoryObjectData&);

  MemoryObjectData(const char* fileName, Size pageOffset);
  ~MemoryObjectData();
  MemoryObjectDataPrivate* d;
};

typedef std::map<Range, MemoryObjectData*> MemoryObjectStorage;
typedef MemoryObjectStorage::value_type MemoryObject;

class ProfilePrivate;

class Profile
{
public:
  enum Mode { Flat, CallGraph };
  enum DetailLevel { Objects, Symbols, Sources };
  Profile();
  ~Profile();

  void load(std::istream& is, Mode mode = CallGraph);
  size_t mmapEventCount() const;
  size_t goodSamplesCount() const;
  size_t badSamplesCount() const;

  void resolveAndFixup(DetailLevel details);

  const MemoryObjectStorage& memoryObjects() const;

private:
  Profile(const Profile&);
  Profile& operator=(const Profile&);

  ProfilePrivate* d;
};

#endif // PROFILE_H
