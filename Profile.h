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

typedef std::map<Address, Count> BranchStorage;
typedef BranchStorage::value_type Branch;

class EntryDataPrivate;
class EntryData
{
public:
  Count count() const;
  const BranchStorage& branches() const;
private:
  friend class MemoryObjectDataPrivate;
  EntryData(const EntryData&);
  EntryData& operator=(const EntryData&);

  explicit EntryData(Count count);
  ~EntryData();
  EntryDataPrivate* d;
};

typedef std::map<Address, EntryData*> EntryStorage;
typedef EntryStorage::value_type Entry;

class SymbolData
{
public:
  SymbolData(const std::string& name)
    : name_(name)
  {}
  const std::string& name() const { return name_; }
private:
  std::string name_;
};

typedef std::map<Range, SymbolData> SymbolStorage;
typedef SymbolStorage::value_type Symbol;

class MemoryObjectDataPrivate;
class MemoryObjectData
{
public:
  Address baseAddress() const;
  const std::string& fileName() const;
  const EntryStorage& entries() const;
private:
  friend class ProfilePrivate;
  MemoryObjectData(const MemoryObjectData&);
  MemoryObjectData& operator=(const MemoryObjectData&);

  explicit MemoryObjectData(const char* fileName);
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
  Profile();
  ~Profile();

  void load(std::istream& is, Mode mode = CallGraph);
  size_t mmapEventCount() const;
  size_t goodSamplesCount() const;
  size_t badSamplesCount() const;

  void fixupBranches();

  const MemoryObjectStorage& memoryObjects() const;
  MemoryObjectStorage& memoryObjects();
  const SymbolStorage& symbols() const;
  SymbolStorage& symbols();
private:
  Profile(const Profile&);
  Profile& operator=(const Profile&);

  ProfilePrivate* d;
};

#endif // PROFILE_H
