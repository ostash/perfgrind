#ifndef PROFILE_H
#define PROFILE_H

#include <istream>
#include <map>
#include <stdint.h>
#include <tr1/unordered_set>

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
  friend class MemoryObjectData;

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
  friend class MemoryObjectData;

  explicit EntryData(Count count);

  Count count_;
  BranchStorage branches_;
  const std::string* sourceFile_;
  size_t sourceLine_;
};

typedef std::map<Address, EntryData*> EntryStorage;
typedef EntryStorage::value_type Entry;

typedef std::tr1::unordered_set<std::string> StringTable;

class AddressResolver;
class MemoryObjectData;
typedef std::map<Range, MemoryObjectData*> MemoryObjectStorage;
typedef MemoryObjectStorage::value_type MemoryObject;

class MemoryObjectData
{
public:
  Address baseAddress() const { return baseAddress_; }
  const std::string& fileName() const { return fileName_; }
  const EntryStorage& entries() const { return entries_; }
  const SymbolStorage& symbols() const { return symbols_; }

private:
  friend class ProfilePrivate;
  MemoryObjectData(const MemoryObjectData&);
  MemoryObjectData& operator=(const MemoryObjectData&);

  MemoryObjectData(const char* fileName, Size pageOffset);
  ~MemoryObjectData();

  EntryData& appendEntry(Address address, Count count);
  void appendBranch(Address from, Address to);

  void resolveEntries(const AddressResolver& resolver, Address loadBase, StringTable* sourceFiles);
  void fixupBranches(const MemoryObjectStorage& objects);

  Address baseAddress_;
  Size pageOffset_;
  EntryStorage entries_;
  SymbolStorage symbols_;
  std::string fileName_;
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
