#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <unistd.h>

namespace {

constexpr uint32_t kArenaSize = 0x20000;
constexpr uint32_t kUserBase = 0x1000;
constexpr uint32_t kMaxFunctions = 16;

constexpr uint64_t kIsolateMagic = 0x49534f4c41544550ULL;      // PETALOSI
constexpr uint64_t kTptMagic = 0x5450545f53544152ULL;          // RATS_TPT
constexpr uint64_t kJsArrayMap = 0x4a5341525f4d4150ULL;        // PAM_RS AJ
constexpr uint64_t kFixedDoubleMap = 0x464441525f4d4150ULL;    // PAM_RADF
constexpr uint64_t kArrayBufferMap = 0x414255465f4d4150ULL;    // PAM_FUBA
constexpr uint64_t kArrayBufferGuard = 0x504c414e45544255ULL;  // UBTENALP
constexpr uint32_t kBytecodeMagic = 0x56384243;                // CB8V
constexpr uint16_t kNativePrint = 0x0000;
constexpr uint16_t kNativeWin = 0x1337;
constexpr uint64_t kWinToken = 0x524154535f4f5242ULL;          // BRO_STAR

constexpr uint32_t kArrayHeaderSize = 0x30;
constexpr uint32_t kFixedHeaderSize = 0x10;
constexpr uint32_t kArrayBufferHeaderSize = 0x40;
constexpr uint32_t kBytecodeHeaderSize = 0x18;
constexpr uint32_t kTptHeaderSize = 0x20;
constexpr uint32_t kTptEntrySize = 0x18;

uint64_t rotl64(uint64_t x, unsigned r) {
    return (x << r) | (x >> (64 - r));
}

uint64_t splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

uint32_t align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

std::string lower(std::string s) {
    for (char& ch : s) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return s;
}

uint64_t parse_u64(const std::string& text) {
    size_t pos = 0;
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
    }
    uint64_t value = std::stoull(text, &pos, base);
    if (pos != text.size()) {
        throw std::runtime_error("bad integer");
    }
    return value;
}

class Arena {
public:
    Arena() : mem_(kArenaSize, 0), top_(kUserBase) {}

    uint32_t alloc(uint32_t size, uint32_t alignment = 0x10) {
        top_ = align_up(top_, alignment);
        if (size == 0 || top_ > kArenaSize || size > kArenaSize - top_) {
            throw std::runtime_error("sandbox exhausted");
        }
        uint32_t off = top_;
        top_ += align_up(size, 8);
        std::fill(mem_.begin() + off, mem_.begin() + top_, 0);
        return off;
    }

    bool in_bounds(uint64_t off, uint64_t size) const {
        return off <= kArenaSize && size <= kArenaSize - off;
    }

    uint8_t read8(uint32_t off) const {
        require(off, 1);
        return mem_[off];
    }

    uint16_t read16(uint32_t off) const {
        uint16_t value = 0;
        load(off, &value, sizeof(value));
        return value;
    }

    uint32_t read32(uint32_t off) const {
        uint32_t value = 0;
        load(off, &value, sizeof(value));
        return value;
    }

    uint64_t read64(uint32_t off) const {
        uint64_t value = 0;
        load(off, &value, sizeof(value));
        return value;
    }

    void write8(uint32_t off, uint8_t value) {
        require(off, 1);
        mem_[off] = value;
    }

    void write16(uint32_t off, uint16_t value) {
        store(off, &value, sizeof(value));
    }

    void write32(uint32_t off, uint32_t value) {
        store(off, &value, sizeof(value));
    }

    void write64(uint32_t off, uint64_t value) {
        store(off, &value, sizeof(value));
    }

    void write_bytes(uint32_t off, const std::vector<uint8_t>& data) {
        require(off, data.size());
        std::memcpy(mem_.data() + off, data.data(), data.size());
    }

    uint32_t top() const {
        return top_;
    }

private:
    void require(uint64_t off, uint64_t size) const {
        if (!in_bounds(off, size)) {
            throw std::runtime_error("sandbox fault");
        }
    }

    void load(uint32_t off, void* out, size_t size) const {
        require(off, size);
        std::memcpy(out, mem_.data() + off, size);
    }

    void store(uint32_t off, const void* in, size_t size) {
        require(off, size);
        std::memcpy(mem_.data() + off, in, size);
    }

    std::vector<uint8_t> mem_;
    uint32_t top_;
};

struct PlanetMap {
    int32_t live = 0;
    uint32_t buckets = 0;
    bool hole = false;
    std::unordered_map<std::string, uint64_t> entries;
};

struct JsArray {
    uint32_t header = 0;
    uint32_t fixed = 0;
    uint32_t data = 0;
    uint32_t length = 0;
};

struct ArrayBuffer {
    uint32_t header = 0;
};

struct OptimizedLoad {
    std::string array_name;
    bool unsafe = false;
};

struct FunctionInfo {
    uint32_t slot = 0;
};

class VM {
public:
    VM() {
        std::random_device rd;
        uint64_t seed = (static_cast<uint64_t>(rd()) << 32) ^ rd();
        if (seed == 0) {
            seed = 0xfeedfacedeadbeefULL;
        }
        cookie_ = splitmix64(seed);

        isolate_off_ = arena_.alloc(0x40, 0x10);
        tpt_off_ = arena_.alloc(kTptHeaderSize + kMaxFunctions * kTptEntrySize, 0x10);

        arena_.write64(isolate_off_ + 0x00, kIsolateMagic);
        arena_.write64(isolate_off_ + 0x08, cookie_);
        arena_.write64(isolate_off_ + 0x10, tpt_off_);
        arena_.write64(isolate_off_ + 0x18, kArenaSize);
        arena_.write64(isolate_off_ + 0x20, 0x53414e44424f5834ULL); // 4XOBDNAS

        arena_.write64(tpt_off_ + 0x00, kTptMagic);
        arena_.write64(tpt_off_ + 0x08, kMaxFunctions);
        arena_.write64(tpt_off_ + 0x10, isolate_off_);
        arena_.write64(tpt_off_ + 0x18, 0);
    }

    void repl() {
        std::cout.setf(std::ios::unitbuf);
        std::cout << "Planetarium d8 build 13.37.0\n";
        std::cout << "type help for shell syntax\n";
        std::string line;
        while (std::cout << "> " && std::getline(std::cin, line)) {
            try {
                if (!handle(line)) {
                    break;
                }
            } catch (const std::exception& ex) {
                std::cout << "err " << ex.what() << "\n";
            }
        }
    }

private:
    uint64_t make_tag(uint32_t off, uint32_t len) const {
        uint64_t mixed = cookie_ ^ (static_cast<uint64_t>(off) << 17) ^
                         (static_cast<uint64_t>(len) << 41) ^ 0x76385f706c616e65ULL;
        return rotl64(splitmix64(mixed), 23) ^ 0xa11ce5eed5eed123ULL;
    }

    uint16_t native_mask() const {
        return static_cast<uint16_t>(((cookie_ >> 13) ^ (cookie_ >> 29) ^ 0xa55a) & 0xffff);
    }

    uint32_t checksum(uint32_t code_off, uint32_t len, uint64_t tag) const {
        uint32_t h = 0x811c9dc5U ^ static_cast<uint32_t>(tag);
        for (uint32_t i = 0; i < len; i++) {
            h ^= arena_.read8(code_off + i);
            h *= 0x01000193U;
            h = (h << 5) | (h >> 27);
        }
        return h ^ static_cast<uint32_t>(tag >> 32) ^ 0x44387621U;
    }

    static uint64_t name_hash(const std::string& name) {
        uint64_t h = 0xcbf29ce484222325ULL;
        for (uint8_t ch : name) {
            h ^= ch;
            h *= 0x100000001b3ULL;
        }
        return h;
    }

    std::vector<std::string> split(const std::string& line) {
        std::istringstream iss(line);
        std::vector<std::string> words;
        std::string word;
        while (iss >> word) {
            words.push_back(word);
        }
        return words;
    }

    bool handle(const std::string& line) {
        auto words = split(line);
        if (words.empty()) {
            return true;
        }
        std::string cmd = lower(words[0]);

        if (cmd == "quit" || cmd == "exit") {
            return false;
        }
        if (cmd == "help") {
            return help();
        }
        if (cmd == "m.new") {
            need(words, 3);
            return map_new(words[1], parse_u64(words[2]));
        }
        if (cmd == "m.set") {
            need(words, 5);
            return map_set(words[1], words[2], parse_u64(words[4]));
        }
        if (cmd == "m.del") {
            need(words, 3);
            return map_del(words[1], words[2]);
        }
        if (cmd == "a.new") {
            need(words, 3);
            return array_new(words[1], parse_u64(words[2]));
        }
        if (cmd == "b.new") {
            need(words, 3);
            return buffer_new(words[1], parse_u64(words[2]));
        }
        if (cmd == "o.new") {
            need(words, 4);
            return opt_new(words[1], words[2], words[3]);
        }
        if (cmd == "o.read") {
            need(words, 3);
            return opt_read(words[1], parse_u64(words[2]));
        }
        if (cmd == "o.write") {
            need(words, 4);
            return opt_write(words[1], parse_u64(words[2]), parse_u64(words[3]));
        }
        if (cmd == "dv.read") {
            need(words, 3);
            return dv_read(words[1], parse_u64(words[2]));
        }
        if (cmd == "dv.write") {
            need(words, 4);
            return dv_write(words[1], parse_u64(words[2]), parse_u64(words[3]));
        }
        if (cmd == "fn.new") {
            need(words, 2);
            return fn_new(words[1]);
        }
        if (cmd == "fn.call") {
            need(words, 2);
            return fn_call(words[1]);
        }

        throw std::runtime_error("unknown command");
    }

    static void need(const std::vector<std::string>& words, size_t count) {
        if (words.size() != count) {
            throw std::runtime_error("wrong arity");
        }
    }

    bool help() {
        std::cout
            << "m.new <map> <buckets>\n"
            << "m.set <map> <key> = <u64>\n"
            << "m.del <map> <key>\n"
            << "a.new <array> <length>\n"
            << "b.new <buffer> <byte_length>\n"
            << "o.new <stub> <map> <array>\n"
            << "o.read <stub> <index>\n"
            << "o.write <stub> <index> <u64>\n"
            << "dv.read <buffer> <offset>\n"
            << "dv.write <buffer> <offset> <u64>\n"
            << "fn.new <function>\n"
            << "fn.call <function>\n";
        return true;
    }

    bool map_new(const std::string& name, uint64_t buckets) {
        if (maps_.count(name)) {
            throw std::runtime_error("duplicate map");
        }
        if (buckets < 4 || buckets > 0x100 || (buckets & (buckets - 1)) != 0) {
            throw std::runtime_error("bucket count must be power-of-two");
        }
        PlanetMap map;
        map.buckets = static_cast<uint32_t>(buckets);
        maps_[name] = std::move(map);
        std::cout << "ok map\n";
        return true;
    }

    bool map_set(const std::string& name, const std::string& key, uint64_t value) {
        PlanetMap& map = must_map(name);
        if (map.entries.size() + static_cast<size_t>(map.hole) >= map.buckets - 1) {
            throw std::runtime_error("map rehash disabled");
        }
        if (key == "@@hole") {
            if (!map.hole) {
                map.live++;
                map.hole = true;
            }
            std::cout << "ok\n";
            return true;
        }
        if (!map.entries.count(key)) {
            map.live++;
        }
        map.entries[key] = value;
        std::cout << "ok\n";
        return true;
    }

    bool map_del(const std::string& name, const std::string& key) {
        PlanetMap& map = must_map(name);
        if (key == "@@hole" && map.hole) {
            map.hole = false;
            if (map.live > static_cast<int32_t>(map.buckets / 2)) {
                map.live -= static_cast<int32_t>(map.buckets + 7);
            } else {
                map.live--;
            }
            std::cout << "ok\n";
            return true;
        }

        auto it = map.entries.find(key);
        if (it == map.entries.end()) {
            throw std::runtime_error("missing key");
        }
        map.entries.erase(it);
        map.live--;
        std::cout << "ok\n";
        return true;
    }

    bool array_new(const std::string& name, uint64_t length64) {
        if (arrays_.count(name)) {
            throw std::runtime_error("duplicate array");
        }
        if (length64 == 0 || length64 > 0x1000) {
            throw std::runtime_error("bad array length");
        }
        uint32_t length = static_cast<uint32_t>(length64);
        uint32_t header = arena_.alloc(kArrayHeaderSize, 0x10);
        uint32_t fixed = arena_.alloc(kFixedHeaderSize + length * 8, 0x10);
        uint32_t data = fixed + kFixedHeaderSize;

        arena_.write64(header + 0x00, kJsArrayMap);
        arena_.write64(header + 0x08, 0);
        arena_.write64(header + 0x10, fixed);
        arena_.write64(header + 0x18, static_cast<uint64_t>(length) << 1);
        arena_.write64(header + 0x20, length);
        arena_.write64(header + 0x28, 0x444f55424c455321ULL);

        arena_.write64(fixed + 0x00, kFixedDoubleMap);
        arena_.write64(fixed + 0x08, static_cast<uint64_t>(length) << 1);
        for (uint32_t i = 0; i < length; i++) {
            arena_.write64(data + i * 8, 0x4141414100000000ULL | i);
        }

        arrays_[name] = JsArray{header, fixed, data, length};
        std::cout << "ok array\n";
        return true;
    }

    bool buffer_new(const std::string& name, uint64_t size64) {
        if (buffers_.count(name)) {
            throw std::runtime_error("duplicate buffer");
        }
        if (size64 < 8 || size64 > 0x4000) {
            throw std::runtime_error("bad buffer length");
        }
        uint32_t size = static_cast<uint32_t>(size64);
        uint32_t header = arena_.alloc(kArrayBufferHeaderSize, 0x10);
        uint32_t backing = arena_.alloc(size, 0x10);

        arena_.write64(header + 0x00, kArrayBufferMap);
        arena_.write64(header + 0x08, 0);
        arena_.write64(header + 0x10, 0);
        arena_.write64(header + 0x18, size);
        arena_.write64(header + 0x20, backing);
        arena_.write64(header + 0x28, kArrayBufferGuard);
        arena_.write64(header + 0x30, cookie_ ^ backing);
        arena_.write64(header + 0x38, 0);

        buffers_[name] = ArrayBuffer{header};
        std::cout << "ok buffer\n";
        return true;
    }

    bool opt_new(const std::string& name, const std::string& map_name, const std::string& array_name) {
        if (opts_.count(name)) {
            throw std::runtime_error("duplicate stub");
        }
        PlanetMap& map = must_map(map_name);
        must_array(array_name);

        OptimizedLoad opt;
        opt.array_name = array_name;
        opt.unsafe = map.live < 0;
        opts_[name] = opt;
        std::cout << "ok optimized\n";
        return true;
    }

    bool opt_read(const std::string& name, uint64_t index) {
        OptimizedLoad& opt = must_opt(name);
        JsArray& array = must_array(opt.array_name);
        if (!opt.unsafe && index >= array.length) {
            throw std::runtime_error("bounds");
        }
        if (index > (std::numeric_limits<uint64_t>::max() - array.data) / 8) {
            throw std::runtime_error("address overflow");
        }
        uint64_t off = static_cast<uint64_t>(array.data) + index * 8;
        if (!arena_.in_bounds(off, 8)) {
            throw std::runtime_error("sandbox fault");
        }
        std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0')
                  << arena_.read64(static_cast<uint32_t>(off))
                  << std::dec << std::setfill(' ') << "\n";
        return true;
    }

    bool opt_write(const std::string& name, uint64_t index, uint64_t value) {
        OptimizedLoad& opt = must_opt(name);
        JsArray& array = must_array(opt.array_name);
        if (!opt.unsafe && index >= array.length) {
            throw std::runtime_error("bounds");
        }
        if (index > (std::numeric_limits<uint64_t>::max() - array.data) / 8) {
            throw std::runtime_error("address overflow");
        }
        uint64_t off = static_cast<uint64_t>(array.data) + index * 8;
        if (!arena_.in_bounds(off, 8)) {
            throw std::runtime_error("sandbox fault");
        }
        arena_.write64(static_cast<uint32_t>(off), value);
        std::cout << "ok\n";
        return true;
    }

    bool dv_read(const std::string& name, uint64_t off) {
        ArrayBuffer& buffer = must_buffer(name);
        uint64_t length = arena_.read64(buffer.header + 0x18);
        uint64_t backing = arena_.read32(buffer.header + 0x20);
        if (off > length || 8 > length - off) {
            throw std::runtime_error("dataview bounds");
        }
        uint64_t absolute = backing + off;
        if (!arena_.in_bounds(absolute, 8)) {
            throw std::runtime_error("sandbox fault");
        }
        std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0')
                  << arena_.read64(static_cast<uint32_t>(absolute))
                  << std::dec << std::setfill(' ') << "\n";
        return true;
    }

    bool dv_write(const std::string& name, uint64_t off, uint64_t value) {
        ArrayBuffer& buffer = must_buffer(name);
        uint64_t length = arena_.read64(buffer.header + 0x18);
        uint64_t backing = arena_.read32(buffer.header + 0x20);
        if (off > length || 8 > length - off) {
            throw std::runtime_error("dataview bounds");
        }
        uint64_t absolute = backing + off;
        if (!arena_.in_bounds(absolute, 8)) {
            throw std::runtime_error("sandbox fault");
        }
        arena_.write64(static_cast<uint32_t>(absolute), value);
        std::cout << "ok\n";
        return true;
    }

    bool fn_new(const std::string& name) {
        if (functions_.count(name)) {
            throw std::runtime_error("duplicate function");
        }
        if (next_slot_ >= kMaxFunctions) {
            throw std::runtime_error("trusted table full");
        }
        uint32_t slot = next_slot_++;
        uint32_t bc = compile_default_bytecode();
        uint32_t len = arena_.read32(bc + 0x04);
        uint64_t tag = arena_.read64(bc + 0x08);
        uint32_t entry = entry_off(slot);
        arena_.write32(entry + 0x00, bc);
        arena_.write32(entry + 0x04, len);
        arena_.write64(entry + 0x08, tag);
        arena_.write64(entry + 0x10, name_hash(name) ^ cookie_);
        functions_[name] = FunctionInfo{slot};
        std::cout << "ok function\n";
        return true;
    }

    bool fn_call(const std::string& name) {
        FunctionInfo& fn = must_function(name);
        execute(fn.slot);
        return true;
    }

    uint32_t compile_default_bytecode() {
        std::vector<uint8_t> code;
        emit_const(code, 0x2a);
        emit_call(code, kNativePrint);
        code.push_back(0xff);
        return install_bytecode(code);
    }

    void emit_const(std::vector<uint8_t>& code, uint64_t value) {
        code.push_back(0x41);
        uint64_t encoded = value ^ cookie_;
        for (unsigned i = 0; i < 8; i++) {
            code.push_back(static_cast<uint8_t>((encoded >> (i * 8)) & 0xff));
        }
    }

    void emit_call(std::vector<uint8_t>& code, uint16_t native_id) {
        code.push_back(0x52);
        uint16_t encoded = native_id ^ native_mask();
        code.push_back(static_cast<uint8_t>(encoded & 0xff));
        code.push_back(static_cast<uint8_t>(encoded >> 8));
    }

    uint32_t install_bytecode(const std::vector<uint8_t>& code) {
        if (code.empty() || code.size() > 0x80) {
            throw std::runtime_error("bad bytecode length");
        }
        uint32_t off = arena_.alloc(kBytecodeHeaderSize + static_cast<uint32_t>(code.size()), 0x10);
        uint32_t len = static_cast<uint32_t>(code.size());
        uint64_t tag = make_tag(off, len);
        arena_.write32(off + 0x00, kBytecodeMagic);
        arena_.write32(off + 0x04, len);
        arena_.write64(off + 0x08, tag);
        arena_.write32(off + 0x10, 0);
        arena_.write32(off + 0x14, 0);
        arena_.write_bytes(off + kBytecodeHeaderSize, code);
        arena_.write32(off + 0x10, checksum(off + kBytecodeHeaderSize, len, tag));
        return off;
    }

    uint32_t entry_off(uint32_t slot) const {
        return tpt_off_ + kTptHeaderSize + slot * kTptEntrySize;
    }

    void execute(uint32_t slot) {
        uint32_t entry = entry_off(slot);
        uint32_t off = arena_.read32(entry + 0x00);
        uint32_t entry_len = arena_.read32(entry + 0x04);
        uint64_t entry_tag = arena_.read64(entry + 0x08);

        if ((off & 0xf) != 0 || !arena_.in_bounds(off, kBytecodeHeaderSize)) {
            throw std::runtime_error("bad trusted pointer");
        }
        uint32_t magic = arena_.read32(off + 0x00);
        uint32_t len = arena_.read32(off + 0x04);
        uint64_t tag = arena_.read64(off + 0x08);
        uint32_t stored_checksum = arena_.read32(off + 0x10);
        if (magic != kBytecodeMagic || len == 0 || len > 0x80 || len != entry_len) {
            throw std::runtime_error("bytecode header rejected");
        }
        if (tag != make_tag(off, len) || entry_tag != tag) {
            throw std::runtime_error("trusted tag mismatch");
        }
        if (!arena_.in_bounds(off + kBytecodeHeaderSize, len)) {
            throw std::runtime_error("bytecode outside sandbox");
        }
        if (stored_checksum != checksum(off + kBytecodeHeaderSize, len, tag)) {
            throw std::runtime_error("bytecode checksum mismatch");
        }

        uint64_t acc = 0;
        uint32_t pc = 0;
        uint32_t gas = 64;
        while (pc < len && gas-- > 0) {
            uint8_t op = arena_.read8(off + kBytecodeHeaderSize + pc++);
            if (op == 0x41) {
                if (pc + 8 > len) {
                    throw std::runtime_error("truncated const");
                }
                uint64_t encoded = arena_.read64(off + kBytecodeHeaderSize + pc);
                pc += 8;
                acc = encoded ^ cookie_;
            } else if (op == 0x52) {
                if (pc + 2 > len) {
                    throw std::runtime_error("truncated call");
                }
                uint16_t encoded = arena_.read16(off + kBytecodeHeaderSize + pc);
                pc += 2;
                native_call(encoded ^ native_mask(), acc);
            } else if (op == 0x2b) {
                if (pc + 8 > len) {
                    throw std::runtime_error("truncated add");
                }
                uint64_t encoded = arena_.read64(off + kBytecodeHeaderSize + pc);
                pc += 8;
                acc += encoded ^ cookie_;
            } else if (op == 0xff) {
                std::cout << "ret 0x" << std::hex << acc << std::dec << "\n";
                return;
            } else {
                throw std::runtime_error("illegal bytecode");
            }
        }
        throw std::runtime_error("bytecode did not halt");
    }

    void native_call(uint16_t native_id, uint64_t acc) {
        if (native_id == kNativePrint) {
            std::cout << "native.print 0x" << std::hex << acc << std::dec << "\n";
            return;
        }
        if (native_id == kNativeWin && acc == kWinToken) {
            win();
            return;
        }
        std::cout << "native.denied\n";
    }

    void win() {
        std::array<const char*, 3> paths = {"./flag.txt", "/flag.txt", "flag.txt"};
        for (const char* path : paths) {
            std::ifstream flag(path);
            if (flag.good()) {
                std::string text;
                std::getline(flag, text);
                std::cout << text << "\n";
                return;
            }
        }
        std::cout << "flag file missing\n";
    }

    PlanetMap& must_map(const std::string& name) {
        auto it = maps_.find(name);
        if (it == maps_.end()) {
            throw std::runtime_error("missing map");
        }
        return it->second;
    }

    JsArray& must_array(const std::string& name) {
        auto it = arrays_.find(name);
        if (it == arrays_.end()) {
            throw std::runtime_error("missing array");
        }
        return it->second;
    }

    ArrayBuffer& must_buffer(const std::string& name) {
        auto it = buffers_.find(name);
        if (it == buffers_.end()) {
            throw std::runtime_error("missing buffer");
        }
        return it->second;
    }

    OptimizedLoad& must_opt(const std::string& name) {
        auto it = opts_.find(name);
        if (it == opts_.end()) {
            throw std::runtime_error("missing stub");
        }
        return it->second;
    }

    FunctionInfo& must_function(const std::string& name) {
        auto it = functions_.find(name);
        if (it == functions_.end()) {
            throw std::runtime_error("missing function");
        }
        return it->second;
    }

    Arena arena_;
    uint64_t cookie_ = 0;
    uint32_t isolate_off_ = 0;
    uint32_t tpt_off_ = 0;
    uint32_t next_slot_ = 0;

    std::unordered_map<std::string, PlanetMap> maps_;
    std::unordered_map<std::string, JsArray> arrays_;
    std::unordered_map<std::string, ArrayBuffer> buffers_;
    std::unordered_map<std::string, OptimizedLoad> opts_;
    std::unordered_map<std::string, FunctionInfo> functions_;
};

} // namespace

int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    alarm(120);
    try {
        VM vm;
        vm.repl();
    } catch (const std::exception& ex) {
        std::cerr << "fatal: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
