#pragma once

#include <cstdint>
#include <istream>
#include <map>
#include <unordered_set>

using Address = std::uint64_t;
using Count = std::uint64_t;
using Size = std::uint64_t;
using Offset = std::int64_t;

class Range
{
public:
  Range(Address start, Address end)
  : start_(start)
  , end_(end)
  {}

  explicit Range(Address value)
  : Range(value, value + 1)
  {}

  Address start() const { return start_; }
  Address end() const { return end_; }
  Size length() const { return end_ - start_; }
  Range adjusted(Offset offset) const { return Range(start_ + offset, end_ + offset); }

  bool operator<(const Range& rhs) const { return end_ <= rhs.start_; }

private:
  Address start_;
  Address end_;
};

std::ostream& operator<<(std::ostream& os, const Range& range);

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

typedef std::unordered_set<std::string> StringTable;

class AddressResolver;
class MemoryObjectData;
using MemoryObjectStorage = std::map<Range, MemoryObjectData>;
using MemoryObject = MemoryObjectStorage::value_type;

class MemoryObjectData
{
public:
  MemoryObjectData(const char* fileName, Size pageOffset);
  ~MemoryObjectData();
  MemoryObjectData(const MemoryObjectData&) = delete;
  MemoryObjectData& operator=(const MemoryObjectData&) = delete;

  Address baseAddress() const { return baseAddress_; }
  const std::string& fileName() const { return fileName_; }
  const EntryStorage& entries() const { return entries_; }
  const SymbolStorage& symbols() const { return symbols_; }

private:
  friend class Profile;

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

namespace pe
{
struct mmap_event;
struct sample_event;
} // namespace pe
class Profile
{
public:
  enum Mode { Flat, CallGraph };
  enum DetailLevel { Objects, Symbols, Sources };
  Profile() = default;

  void load(std::istream& is, Mode mode = CallGraph);
  size_t mmapEventCount() const { return mmapEventCount_; }
  size_t goodSamplesCount() const { return goodSamplesCount_; }
  size_t nonUserSamples() const { return nonUserSamples_; }
  size_t unmappedSamples() const { return unmappedSamples_; }

  void resolveAndFixup(DetailLevel details);

  const MemoryObjectStorage& memoryObjects() const { return memoryObjects_; }

private:
  Profile(const Profile&);
  Profile& operator=(const Profile&);

  void processMmapEvent(const pe::mmap_event& event);
  void processSampleEvent(const pe::sample_event& event, Profile::Mode mode);

  void cleanupMemoryObjects();

  MemoryObjectStorage memoryObjects_;
  StringTable sourceFiles_;

  size_t mmapEventCount_ = 0;
  size_t goodSamplesCount_ = 0;
  size_t nonUserSamples_ = 0;
  size_t unmappedSamples_ = 0;
};
