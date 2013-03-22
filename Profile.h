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

class EntryData
{
public:
  explicit EntryData(Count count)
    : count_(count)
  {}

  Count count() const { return count_; }
  const BranchStorage& branches() const { return branches_; }

  void addCount(Count count) { count_ += count; }
  void appendBranch(Address address, Count count = 1);

  void swap(EntryData& other)
  {
    std::swap(count_, other.count_);
    branches_.swap(other.branches_);
  }

private:
  Count count_;
  BranchStorage branches_;
};

typedef std::map<Address, EntryData> EntryStorage;
typedef EntryStorage::value_type Entry;


inline bool operator<(const Entry& entry, Address value)
{
  return entry.first < value;
}

inline bool operator<(Address value, const Entry& entry)
{
  return value < entry.first;
}

class MemoryObjectData
{
public:
  /// Constructs memory object data
  explicit MemoryObjectData(const char* fileName)
    : fileName_(fileName)
  {}

  /// Returns full path to object file
  const std::string& fileName() const { return fileName_; }

  void setBaseAddress(Address value) { baseAddress_ = value; }
  Address baseAddress() const { return baseAddress_; }
private:
  const std::string fileName_;
  Address baseAddress_;
};

typedef std::map<Range, MemoryObjectData> MemoryObjectStorage;
typedef MemoryObjectStorage::value_type MemoryObject;

class SymbolData
{
public:
  SymbolData(const std::string& name)
    : name_(name)
  {}
private:
  std::string name_;
};

typedef std::map<Range, SymbolData> SymbolStorage;
typedef SymbolStorage::value_type Symbol;

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
  const EntryStorage& entries() const;
private:
  Profile(const Profile&);
  Profile& operator=(const Profile&);

  ProfilePrivate* d;
};

#endif // PROFILE_H
