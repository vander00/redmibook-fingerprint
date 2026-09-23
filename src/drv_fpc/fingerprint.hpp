/*
Copyright (C) 2022  pom@vro.life

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#ifndef __fingerprint_hpp__
#define __fingerprint_hpp__

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <limits>

#include "cvext.hpp"

namespace fpc {

// The first five frames build distinct-area coverage. The remaining frames
// add alignable angle, pressure, and nearby-placement variations.
static constexpr size_t DISTINCT_AREA_POSITION_TEMPLATES = 5;
static constexpr size_t ENROLLMENT_POSITION_TEMPLATES = 7;
// Older records can contain ten templates; keep reading and matching all of them.
static constexpr size_t MAX_POSITION_TEMPLATES = 10;
static constexpr double MIN_NEW_POSITION_AREA_RATIO = 0.10;

enum class EnrollmentSampleResult {
    accepted,
    unmatchable,
    insufficient_new_area,
};

struct Fingerprint
{
    struct LearningStats {
        uint32_t hits{};
        uint32_t opportunities{};
        uint32_t sequence{};
    };

    std::string _user{};
    std::string _name{};
    cv::Mat _fingerprint{};
    cv::Mat _mask{};
    std::vector<cv::Mat> _templates{};
    size_t _anchor_count{};
    std::vector<LearningStats> _learning_stats{};
    uint32_t _learning_sequence{};
    cv::Mat _pending_template{}; // Never persisted or used for verification.
    unsigned _unsaved_usage{};

    Fingerprint() = default;
    Fingerprint(Fingerprint&&) = default;
    Fingerprint(const Fingerprint&) = default;
    ~Fingerprint() = default;

    Fingerprint& operator =(Fingerprint&&) = default;
    Fingerprint& operator =(const Fingerprint&) = default;

    EnrollmentSampleResult merge(const cv::Mat& img);
    bool match(
        const cv::Mat& img,
        float legacy_min_score,
        float position_min_score,
        bool filter,
        size_t* matched_template = nullptr) const;
    bool strong_anchor_match(const cv::Mat& img) const;
    bool observe_verified_scan(const cv::Mat& img, bool unique_anchor);
    void record_verification_use(size_t matched_template);
    bool usage_save_due() const { return _unsaved_usage >= 20; }
    void usage_saved() { _unsaved_usage = 0; }

    size_t total() const;
    size_t template_count() const { return _templates.size(); }

    void write(cv::FileStorage& fstorage, int idx) const;
    void read(cv::FileStorage& fstorage, int idx);

    static bool is_any(const std::string& name) {
        return name.empty() or name == "any";
    }
};

class FingerprintStorage
{
    std::string _filename{};
    std::vector<unsigned char> _key{};
    std::unordered_map<std::string, std::unordered_map<std::string, Fingerprint>> _fingerprints{};

public:
    template<typename F>
    void foreach(const std::string& username, F&& fun) {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return;
        }

        for (auto& pair : user->second) {
            auto ret = fun(pair.second);
            if (ret) {
                return;
            }
        }
    }

    size_t get_enrolled_count(const std::string& username) {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return 0;
        }
        return user->second.size();
    }

    void delete_all(const std::string& username)
    {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return;
        }
        user->second.clear();
    }

    bool delete_fingerprint(const std::string& username, const std::string& name)
    {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return false;
        }

        auto print = user->second.find(name);
        if (print != user->second.end()) {
            user->second.erase(print);
            return true;
        }

        return false;
    }

    bool check(const std::string& username, const std::string& name)
    {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return false;
        }

        auto print = user->second.find(name);
        return print != user->second.end();
    }

    void insert_or_update(Fingerprint&& fingerprint);
    Fingerprint* unique_strong_anchor(const std::string& username, const cv::Mat& img);
    bool update_after_verification(Fingerprint& fingerprint, const cv::Mat& img,
                                   bool unique_anchor);
    
    void load();
    bool save();

    void reset() {
        _filename.clear();
        _key.clear();
        _fingerprints.clear();
    }

    void init(const std::string& filename, const std::vector<unsigned char>& key);
};

}

#endif
