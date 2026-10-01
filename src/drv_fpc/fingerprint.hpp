#ifndef FPC_FINGERPRINT_HPP
#define FPC_FINGERPRINT_HPP
#include "native/enrollment.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>
namespace fpc {
constexpr size_t ENROLLMENT_POSITION_TEMPLATES = 13;
struct Fingerprint {
    std::string _user, _name;
    std::vector<unsigned char> _native;
    uint32_t _registration{};
    static bool valid_name(const std::string &name) {
        static constexpr std::array<const char *, 10> names = {
            "left-thumb",         "left-index-finger",  "left-middle-finger", "left-ring-finger",
            "left-little-finger", "right-thumb",        "right-index-finger", "right-middle-finger",
            "right-ring-finger",  "right-little-finger"};
        return std::any_of(names.begin(), names.end(),
                           [&](const char *value) { return name == value; });
    }
    static bool is_any(const std::string &name) { return name.empty() || name == "any"; }
};
std::vector<unsigned char> serialize_native_template(const fpc_loaded_template &data);
class FingerprintStorage {
    using Records = std::map<std::string, std::map<std::string, Fingerprint>>;
    std::string _filename;
    std::vector<unsigned char> _key;
    Records _fingerprints;

  public:
    ~FingerprintStorage();
    std::vector<uint16_t> dead_pixels;
    uint64_t capture_generation = 0;
    bool operation_active = false, sleeping = false, reader_ready = false;
    uint16_t hardware_id = 0x0111;
    template <typename F> void foreach (const std::string &username, F && fn) {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end())
            return;
        std::vector<Fingerprint *> ordered;
        for (auto &pair : user->second)
            ordered.push_back(&pair.second);
        std::sort(ordered.begin(), ordered.end(),
                  [](const auto *a, const auto *b) { return a->_registration < b->_registration; });
        for (auto *fingerprint : ordered)
            if (fn(*fingerprint))
                return;
    }
    size_t get_enrolled_count(const std::string &user) const;
    bool check(const std::string &user, const std::string &name) const;
    bool delete_all(const std::string &user);
    bool delete_fingerprint(const std::string &user, const std::string &name);
    bool insert_or_update(Fingerprint &&fingerprint);
    bool verify(const std::string &user, const std::string &name,
                const fpc_prepared_capture &query);
    void load();
    bool save();
    void reset();
    void init(const std::string &filename, const std::vector<unsigned char> &key);
};
} // namespace fpc
#endif
