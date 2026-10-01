#include "fingerprint.hpp"
#include "crypto.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <jinx/logging.hpp>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
namespace fpc {
namespace {
constexpr std::array<unsigned char, 8> magic = {'F', 'P', 'C', 'N', 'A', 'T', 'V', '1'};
constexpr size_t maximum_file = 16 * 1024 * 1024;
struct Template {
    fpc_loaded_template data{};
    ~Template() { fpc_loaded_template_destroy(&data); }
};
struct Capture {
    fpc_loaded_capture data{};
    ~Capture() { fpc_loaded_capture_destroy(&data); }
};
void append32(std::vector<unsigned char> &data, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        data.push_back(value >> (8 * i));
}
void append_string(std::vector<unsigned char> &data, const std::string &value) {
    if (value.empty() || value.size() > 256 || value.find('\0') != std::string::npos)
        throw std::runtime_error("invalid native record name");
    append32(data, value.size());
    data.insert(data.end(), value.begin(), value.end());
}
struct Reader {
    const std::vector<unsigned char> &bytes;
    size_t offset = 0;
    uint32_t word() {
        if (bytes.size() - offset < 4)
            throw std::runtime_error("truncated native database");
        uint32_t n = 0;
        for (unsigned i = 0; i < 4; ++i)
            n |= uint32_t(bytes[offset++]) << (8 * i);
        return n;
    }
    std::vector<unsigned char> take(size_t count) {
        if (count > bytes.size() - offset)
            throw std::runtime_error("truncated native record");
        std::vector<unsigned char> result(bytes.begin() + offset, bytes.begin() + offset + count);
        offset += count;
        return result;
    }
    std::string string() {
        auto count = word();
        if (!count || count > 256)
            throw std::runtime_error("invalid native name length");
        auto value = take(count);
        if (std::find(value.begin(), value.end(), 0) != value.end())
            throw std::runtime_error("invalid native name");
        return {value.begin(), value.end()};
    }
};
void validate(const std::vector<unsigned char> &bytes) {
    Template owned;
    if (bytes.size() > 200000 ||
        fpc_template_load_default(bytes.data(), bytes.size(), 32, &owned.data) ||
        owned.data.graph.capacity != 32 || owned.data.collection.capacity != 32 ||
        owned.data.collection.count > 32)
        throw std::runtime_error("incompatible native template");
    std::array<bool, 32> seen{};
    for (size_t i = 0; i < 32; ++i) {
        auto slot = owned.data.graph.order[i];
        if (slot >= 32 || seen[slot])
            throw std::runtime_error("invalid retained order");
        seen[slot] = true;
    }
    if (owned.data.graph.protected_count > 32 || owned.data.graph.protected_limit > 32)
        throw std::runtime_error("invalid retained protection");
    for (size_t i = 0; i < owned.data.collection.count; ++i) {
        auto &c = owned.data.collection.captures[i].view;
        if (c.mode != 1 || c.descriptor_bytes != 16 || c.levels != 1 || c.count > 300)
            throw std::runtime_error("incompatible profile300 capture");
    }
}
} // namespace
std::vector<unsigned char> serialize_native_template(const fpc_loaded_template &data) {
    std::vector<fpc_capture_payload_view> views;
    for (size_t i = 0; i < data.collection.count; ++i)
        views.push_back(data.collection.captures[i].view);
    size_t size = 0;
    if (fpc_template_serialize_default(&data.graph, views.data(), views.size(),
                                       data.collection.capacity, data.metadata, 32, nullptr, 0,
                                       &size))
        throw std::runtime_error("native template size failed");
    std::vector<unsigned char> bytes(size);
    if (fpc_template_serialize_default(&data.graph, views.data(), views.size(),
                                       data.collection.capacity, data.metadata, 32, bytes.data(),
                                       bytes.size(), &size))
        throw std::runtime_error("native template serialization failed");
    return bytes;
}
FingerprintStorage::~FingerprintStorage() {
    if (!_key.empty())
        OPENSSL_cleanse(_key.data(), _key.size());
}
void FingerprintStorage::reset() {
    if (!_key.empty())
        OPENSSL_cleanse(_key.data(), _key.size());
    _filename.clear();
    _key.clear();
    _fingerprints.clear();
    dead_pixels.clear();
}
size_t FingerprintStorage::get_enrolled_count(const std::string &username) const {
    auto user = _fingerprints.find(username);
    return user == _fingerprints.end() ? 0 : user->second.size();
}
bool FingerprintStorage::check(const std::string &username, const std::string &name) const {
    auto user = _fingerprints.find(username);
    return user != _fingerprints.end() && user->second.count(name);
}
bool FingerprintStorage::delete_all(const std::string &user) {
    auto before = _fingerprints;
    _fingerprints.erase(user);
    if (save())
        return true;
    _fingerprints = std::move(before);
    return false;
}
bool FingerprintStorage::delete_fingerprint(const std::string &username, const std::string &name) {
    if (!check(username, name))
        return false;
    auto before = _fingerprints;
    _fingerprints[username].erase(name);
    if (save())
        return true;
    _fingerprints = std::move(before);
    return false;
}
bool FingerprintStorage::insert_or_update(Fingerprint &&fingerprint) {
    if (!Fingerprint::valid_name(fingerprint._name))
        throw std::runtime_error("invalid finger name");
    validate(fingerprint._native);
    auto before = _fingerprints;
    auto user = fingerprint._user, name = fingerprint._name;
    if (check(user, name))
        fingerprint._registration = _fingerprints[user][name]._registration;
    else {
        uint32_t last = 0;
        for (const auto &owner : _fingerprints)
            for (const auto &record : owner.second)
                last = std::max(last, record.second._registration);
        if (last == UINT32_MAX)
            return false;
        fingerprint._registration = last + 1;
    }
    _fingerprints[user][name] = std::move(fingerprint);
    if (save())
        return true;
    _fingerprints = std::move(before);
    return false;
}
bool FingerprintStorage::verify(const std::string &user, const std::string &name,
                                const fpc_prepared_capture &query) {
    Capture probe;
    if (fpc_capture_from_prepared(&query, 0, &probe.data))
        throw std::runtime_error("native query allocation failed");
    std::vector<Fingerprint *> records;
    std::vector<std::unique_ptr<Template>> owned;
    std::vector<const fpc_loaded_collection *> collections;
    foreach (user, [&](Fingerprint &record) {
        if (!Fingerprint::is_any(name) && name != record._name)
            return false;
        auto item = std::make_unique<Template>();
        if (fpc_template_load_default(record._native.data(), record._native.size(), 32,
                                      &item->data))
            throw std::runtime_error("native stored template failed");
        collections.push_back(&item->data.collection);
        records.push_back(&record);
        owned.push_back(std::move(item));
        return false;
    })
        ;
    fpc_identification_policy policy{18, 1000, 5, 20};
    fpc_identification_result result{};
    if (fpc_identify_profile300(collections.data(), collections.size(), &probe.data.view,
                                query.confidence, const_cast<uint8_t *>(probe.data.view.membership),
                                (probe.data.view.count + 7) / 8, &policy, &result))
        throw std::runtime_error("native identification failed");
    if (!result.matched)
        return false;
    auto index = static_cast<size_t>(result.selected_template);
    auto &data = owned.at(index)->data;
    fpc_collection_match_result match{};
    if (fpc_match_profile300_collection(&data.collection, &probe.data.view,
                                        const_cast<uint8_t *>(probe.data.view.membership),
                                        (probe.data.view.count + 7) / 8, &match))
        throw std::runtime_error("native update match failed");
    fpc_template_update_policy update_policy{25, 8, 25, 60, 32};
    fpc_template_update_state state{
        102, 1, 1, 1, result.reported_score, static_cast<int8_t>(result.selected_capture), 0, -1};
    uint8_t changed = 0;
    if (fpc_update_template_after_match(&data, &probe.data, query.confidence, query.coverage,
                                        query.quality, match.spatial_scores, match.count,
                                        &update_policy, &state, &changed))
        throw std::runtime_error("native template update failed");
    if (state.changed) {
        auto previous = records[index]->_native;
        records[index]->_native = serialize_native_template(data);
        if (!save()) {
            records[index]->_native = std::move(previous);
            jinx_log_error() << "native adaptation could not be saved";
        }
    }
    return true;
}
void FingerprintStorage::init(const std::string &filename, const std::vector<unsigned char> &key) {
    if (key.size() != 32)
        throw std::runtime_error("invalid database encryption key");
    _filename = filename;
    if (!_key.empty())
        OPENSSL_cleanse(_key.data(), _key.size());
    _key = key;
    load();
}
void FingerprintStorage::load() {
    if (!std::filesystem::exists(_filename)) {
        _fingerprints.clear();
        return;
    }
    auto size = std::filesystem::file_size(_filename);
    if (size < 36 || size > maximum_file)
        throw std::runtime_error("invalid native database size");
    std::ifstream stream(_filename, std::ios::binary);
    std::vector<unsigned char> encrypted(size);
    if (!stream.read(reinterpret_cast<char *>(encrypted.data()), size) ||
        !std::equal(magic.begin(), magic.end(), encrypted.begin()))
        throw std::runtime_error("invalid native database header");
    std::vector<unsigned char> plain(size - 36);
    jinx::SliceConst key{_key.data(), _key.size()};
    if (!crypto::decrypt(EVP_chacha20_poly1305(), {encrypted.data(), 8}, {encrypted.data() + 8, 12},
                         key, {encrypted.data() + 20, plain.size()}, {plain.data(), plain.size()},
                         {encrypted.data() + size - 16, 16}))
        throw std::runtime_error("native database authentication failed");
    Reader reader{plain};
    if (reader.word() != 1 || reader.word() != 300 || reader.word() != 112 || reader.word() != 88 ||
        reader.word() != 26 || reader.word() != hardware_id)
        throw std::runtime_error("native database profile mismatch");
    auto count = reader.word();
    if (count > 1000)
        throw std::runtime_error("too many native records");
    Records parsed;
    std::set<uint32_t> registrations;
    for (uint32_t i = 0; i < count; ++i) {
        Fingerprint print;
        print._registration = reader.word();
        if (!print._registration || !registrations.insert(print._registration).second)
            throw std::runtime_error("invalid native registration");
        print._user = reader.string();
        print._name = reader.string();
        if (!Fingerprint::valid_name(print._name))
            throw std::runtime_error("invalid stored finger name");
        auto length = reader.word();
        if (length > 200000)
            throw std::runtime_error("native template too large");
        print._native = reader.take(length);
        validate(print._native);
        auto user = print._user, name = print._name;
        if (parsed[user].count(name))
            throw std::runtime_error("duplicate native record");
        parsed[user].emplace(name, std::move(print));
    }
    if (reader.offset != plain.size())
        throw std::runtime_error("trailing native database data");
    _fingerprints = std::move(parsed);
}
bool FingerprintStorage::save() {
    try {
        if (_key.size() != 32 || _filename.empty())
            return false;
        std::vector<unsigned char> plain;
        for (uint32_t value : {1u, 300u, 112u, 88u, 26u, uint32_t(hardware_id)})
            append32(plain, value);
        uint32_t count = 0;
        for (auto &user : _fingerprints)
            count += user.second.size();
        if (count > 1000)
            return false;
        append32(plain, count);
        for (auto &user : _fingerprints)
            for (auto &entry : user.second) {
                auto &print = entry.second;
                append32(plain, print._registration);
                append_string(plain, print._user);
                append_string(plain, print._name);
                append32(plain, print._native.size());
                plain.insert(plain.end(), print._native.begin(), print._native.end());
            }
        if (plain.size() > maximum_file - 36)
            return false;
        std::vector<unsigned char> encrypted(plain.size() + 36);
        std::copy(magic.begin(), magic.end(), encrypted.begin());
        if (RAND_bytes(encrypted.data() + 8, 12) != 1)
            return false;
        jinx::SliceConst key{_key.data(), _key.size()};
        if (!crypto::encrypt(EVP_chacha20_poly1305(), {encrypted.data(), 8},
                             {encrypted.data() + 8, 12}, key, {plain.data(), plain.size()},
                             {encrypted.data() + 20, plain.size()},
                             {encrypted.data() + 20 + plain.size(), 16}))
            return false;
        auto directory = std::filesystem::path(_filename).parent_path();
        if (directory.empty())
            directory = ".";
        int parent = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (parent < 0)
            return false;
        std::string pattern = _filename + ".tmp.XXXXXX";
        std::vector<char> temporary_name(pattern.begin(), pattern.end());
        temporary_name.push_back(0);
        int descriptor = mkostemp(temporary_name.data(), O_CLOEXEC);
        std::string temporary = temporary_name.data();
        if (descriptor < 0) {
            close(parent);
            return false;
        }
        if (fchmod(descriptor, 0600) != 0) {
            close(descriptor);
            close(parent);
            unlink(temporary.c_str());
            return false;
        }
        size_t offset = 0;
        bool ok = true;
        while (offset < encrypted.size()) {
            auto written = write(descriptor, encrypted.data() + offset, encrypted.size() - offset);
            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0) {
                ok = false;
                break;
            }
            offset += written;
        }
        if (ok)
            ok = fsync(descriptor) == 0;
        if (close(descriptor) != 0)
            ok = false;
        if (ok)
            ok = rename(temporary.c_str(), _filename.c_str()) == 0;
        if (!ok) {
            unlink(temporary.c_str());
            close(parent);
            return false;
        }
        if (fsync(parent) != 0)
            jinx_log_error() << "native database directory fsync failed: " << strerror(errno);
        close(parent);
        // The rename already committed; reporting failure here would roll back only memory.
        return true;
    } catch (const std::exception &error) {
        jinx_log_error() << "native database save failed: " << error.what();
        return false;
    }
}
} // namespace fpc
