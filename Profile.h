#ifndef PROFILE_H
#define PROFILE_H

#include <istream>
#include <map>
#include <tr1/unordered_map>
#include <stdint.h>

typedef uint64_t Address;
typedef uint64_t Count;
typedef uint64_t Size;

typedef std::tr1::unordered_map<Address, Count> BranchStorage;
typedef BranchStorage::value_type Branch;

class EntryData
{
public:
  explicit EntryData(Count count)
    : count_(count)
    , branches_(0)
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

typedef std::tr1::unordered_map<Address, EntryData> EntryStorage;
typedef EntryStorage::value_type Entry;

class MemoryObjectData
{
public:
  /// Constructs memory object data
  MemoryObjectData(Size size, const char* fileName)
    : size_(size)
    , fileName_(fileName)
  {}

  /// Returns size of object in program image
  uint64_t size() const { return size_; }
  /// Returns full path to object file
  const std::string& fileName() const { return fileName_; }

private:
  const Size size_;
  const std::string fileName_;
};

#ifdef ENABLE_MEMORY_INDEX
typedef std::tr1::unordered_map<Address, MemoryObjectData> MemoryObjectStorage;
#else
typedef std::map<Address, MemoryObjectData> MemoryObjectStorage;
#endif
typedef MemoryObjectStorage::value_type MemoryObject;

class SymbolData
{
private:
  Size size_;
  std::string name_;
};

typedef std::tr1::unordered_map<Address, SymbolData> SymbolStorage;
typedef SymbolStorage::value_type Symbol;

class ProfilePrivate;

class Profile
{
public:
  enum Mode { Flat, CallGraph };
  Profile();
  ~Profile();

  void load(std::istream& is, Mode mode = CallGraph);
  size_t goodSamplesCount() const;
  size_t badSamplesCount() const;

  void fixupBranches();

  const MemoryObjectStorage& memoryObjects() const;
  const SymbolStorage& symbols() const;
  SymbolStorage& symbols();
  const EntryStorage& entries() const;
private:
  Profile(const Profile&);
  Profile& operator=(const Profile&);

  ProfilePrivate* d;
};

#endif // PROFILE_H
