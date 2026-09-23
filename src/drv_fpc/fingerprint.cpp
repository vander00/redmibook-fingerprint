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
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <array>

#include <sys/stat.h>
#include <unistd.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <opencv2/imgproc.hpp>

#include "jinx/logging.hpp"

#include "fingerprint.hpp"
#include "crypto.hpp"

namespace fpc {
using namespace std::string_literals;
namespace {
constexpr std::array<unsigned char, 8> STORAGE_MAGIC{'F', 'P', 'C', 'D', 'B', 'v', '2', '!'};
constexpr size_t STORAGE_NONCE_SIZE = 12;
}

EnrollmentSampleResult Fingerprint::merge(const cv::Mat& img)
{
    if (_fingerprint.empty()) {
        if (not cvext::has_enrollment_features(img)) {
            return EnrollmentSampleResult::unmatchable;
        }
        _fingerprint = img.clone();
        _mask.create(_fingerprint.size(), CV_32F);
        _mask.setTo(1.0F);
        _templates.push_back(img.clone());
        _anchor_count = 1;
        _learning_stats.emplace_back();
        return EnrollmentSampleResult::accepted;
    }

    bool linked = false;
    bool repeated_position = false;
    for (const auto& saved : _templates) {
        double overlap_ratio = 0.0;
        if (cvext::enrollment_match(saved, img, overlap_ratio)) {
            linked = true;
            if (overlap_ratio > 1.0 - MIN_NEW_POSITION_AREA_RATIO) {
                repeated_position = true;
            }
        }
    }
    if (not linked) {
        return EnrollmentSampleResult::unmatchable;
    }
    if (_templates.size() < DISTINCT_AREA_POSITION_TEMPLATES and repeated_position) {
        return EnrollmentSampleResult::insufficient_new_area;
    }

    if (_templates.size() < ENROLLMENT_POSITION_TEMPLATES) {
        _templates.push_back(img.clone());
        ++_anchor_count;
        _learning_stats.emplace_back();
    }
    return EnrollmentSampleResult::accepted;
}

bool Fingerprint::match(
    const cv::Mat &img,
    float legacy_min_score,
    float position_min_score,
    bool filter,
    size_t* matched_template) const
{
    if (matched_template != nullptr) {
        *matched_template = std::numeric_limits<size_t>::max();
    }
    // Position-specific frames avoid forcing every verification press to align
    // against a large stitched canvas. They use the same hardened
    // SIFT/RANSAC/SSIM acceptance path and threshold as the legacy template;
    // unlike PR #8, no uncalibrated classifier can accept a print by itself.
    for (size_t idx = 0; idx < _templates.size(); ++idx) {
        cv::Mat mask{_templates[idx].size(), CV_32F};
        mask.setTo(1.0F);
        if (cvext::match(_templates[idx], mask, img, 4, position_min_score, filter)) {
            std::cout << "match: position-template=" << idx << std::endl;
            if (matched_template != nullptr) {
                *matched_template = idx;
            }
            return true;
        }
    }

    // Old databases contain only the stitched template. New databases keep a
    // first-scan print/mask for storage compatibility, but do not use its lower legacy threshold:
    // trying both paths would multiply false-accept opportunities and defeat
    // the stricter per-position matcher.
    if (_templates.empty()) {
        return cvext::match(_fingerprint, _mask, img, 4, legacy_min_score, filter);
    }
    return false;
}

bool Fingerprint::strong_anchor_match(const cv::Mat& img) const
{
    for (size_t idx = 0; idx < std::min(_anchor_count, _templates.size()); ++idx) {
        cvext::MatchEvidence evidence{};
        if (cvext::strong_match(_templates[idx], img, 0.30, evidence)) {
            return true;
        }
    }
    return false;
}

void Fingerprint::record_verification_use(size_t matched_template)
{
    if (_learning_stats.size() <= _anchor_count) {
        return;
    }
    // Every successful verification is a chance for a learned position to
    // contribute. A hit is credited only when no original anchor matched.
    for (size_t idx = _anchor_count; idx < _learning_stats.size(); ++idx) {
        auto& stats = _learning_stats[idx];
        if (stats.opportunities < static_cast<uint32_t>(std::numeric_limits<int>::max())) {
            ++stats.opportunities;
        }
    }
    if (matched_template >= _anchor_count and
        matched_template < _learning_stats.size()) {
        auto& winner = _learning_stats[matched_template];
        if (winner.hits < static_cast<uint32_t>(std::numeric_limits<int>::max())) {
            ++winner.hits;
        }
    }
    if (_unsaved_usage < std::numeric_limits<unsigned>::max()) {
        ++_unsaved_usage;
    }
}

bool Fingerprint::observe_verified_scan(const cv::Mat& img, bool unique_anchor)
{
    if (not unique_anchor or not strong_anchor_match(img) or
        _anchor_count == 0 or _anchor_count >= MAX_POSITION_TEMPLATES) {
        return false;
    }

    // Keep only genuinely new positions. A strong match to an original scan
    // is mandatory even when the candidate resembles a learned position.
    for (const auto& saved : _templates) {
        double overlap = 0.0;
        if (cvext::enrollment_match(saved, img, overlap) and
            overlap > 1.0 - MIN_NEW_POSITION_AREA_RATIO) {
            return false;
        }
    }

    size_t replace = std::numeric_limits<size_t>::max();
    if (_templates.size() >= MAX_POSITION_TEMPLATES) {
        // A learned position must have had ten chances to prove useful before
        // it can be replaced. Smooth sparse hit rates so new slots survive.
        for (size_t idx = _anchor_count; idx < _learning_stats.size(); ++idx) {
            const auto& stats = _learning_stats[idx];
            if (stats.opportunities < 10) {
                continue;
            }
            if (replace == std::numeric_limits<size_t>::max()) {
                replace = idx;
                continue;
            }
            const auto& weakest = _learning_stats[replace];
            const uint64_t candidate_rate = (uint64_t(stats.hits) + 1) * (uint64_t(weakest.opportunities) + 10);
            const uint64_t weakest_rate = (uint64_t(weakest.hits) + 1) * (uint64_t(stats.opportunities) + 10);
            if (candidate_rate < weakest_rate or
                (candidate_rate == weakest_rate and stats.sequence < weakest.sequence)) {
                replace = idx;
            }
        }
        if (replace == std::numeric_limits<size_t>::max()) {
            return false;
        }
    }

    cvext::MatchEvidence pending_evidence{};
    if (_pending_template.empty() or
        not cvext::strong_match(_pending_template, img, 0.75, pending_evidence)) {
        _pending_template = img.clone();
        return false;
    }

    _pending_template.release();
    LearningStats fresh{};
    if (_learning_sequence < static_cast<uint32_t>(std::numeric_limits<int>::max())) {
        ++_learning_sequence;
    }
    fresh.sequence = _learning_sequence;
    if (replace == std::numeric_limits<size_t>::max()) {
        _templates.push_back(img.clone());
        _learning_stats.push_back(fresh);
    } else {
        _templates[replace] = img.clone();
        _learning_stats[replace] = fresh;
    }
    return true;
}

size_t Fingerprint::total() const
{
    auto sum = cv::sum(_mask);
    return static_cast<size_t>(sum[0]);
}

void Fingerprint::write(cv::FileStorage& fstorage, int idx) const
{
    std::string name{};
    
    name = "user"s + std::to_string(idx);
    fstorage << name << _user;

    name = "name"s + std::to_string(idx);
    fstorage << name << _name;

    name = "print"s + std::to_string(idx);
    fstorage << name << _fingerprint;

    name = "mask"s + std::to_string(idx);
    fstorage << name << _mask;

    name = "template_count"s + std::to_string(idx);
    fstorage << name << static_cast<int>(_templates.size());
    name = "anchor_count"s + std::to_string(idx);
    fstorage << name << static_cast<int>(_anchor_count);
    name = "learning_sequence"s + std::to_string(idx);
    fstorage << name << static_cast<int>(_learning_sequence);

    for (size_t template_idx = 0; template_idx < _templates.size(); ++template_idx) {
        name = "template"s + std::to_string(idx) + "_"s + std::to_string(template_idx);
        fstorage << name << _templates[template_idx];
        if (template_idx >= _anchor_count and template_idx < _learning_stats.size()) {
            const auto& stats = _learning_stats[template_idx];
            const auto suffix = std::to_string(idx) + "_"s + std::to_string(template_idx);
            fstorage << "learned_hits"s + suffix << static_cast<int>(stats.hits);
            fstorage << "learned_opportunities"s + suffix << static_cast<int>(stats.opportunities);
            fstorage << "learned_sequence"s + suffix << static_cast<int>(stats.sequence);
        }
    }
}

void Fingerprint::read(cv::FileStorage& fstorage, int idx)
{
    std::string name{};

    name = "user"s + std::to_string(idx);
    _user = fstorage[name].string();

    name = "name"s + std::to_string(idx);
    _name = fstorage[name].string();

    name = "print"s + std::to_string(idx);
    _fingerprint = fstorage[name].mat();

    name = "mask"s + std::to_string(idx);
    _mask = fstorage[name].mat();

    _templates.clear();
    name = "template_count"s + std::to_string(idx);
    int template_count = fstorage[name].empty() ? 0 : static_cast<int>(fstorage[name]);
    template_count = std::clamp(template_count, 0, static_cast<int>(MAX_POSITION_TEMPLATES));
    for (int template_idx = 0; template_idx < template_count; ++template_idx) {
        name = "template"s + std::to_string(idx) + "_"s + std::to_string(template_idx);
        if (not fstorage[name].empty()) {
            _templates.push_back(fstorage[name].mat());
        }
    }
    name = "anchor_count"s + std::to_string(idx);
    _anchor_count = fstorage[name].empty()
        ? _templates.size() // Pre-adaptation records are all trusted originals.
        : static_cast<size_t>(std::clamp(static_cast<int>(fstorage[name]), 0,
                                          static_cast<int>(_templates.size())));
    name = "learning_sequence"s + std::to_string(idx);
    _learning_sequence = fstorage[name].empty() ? 0
        : static_cast<uint32_t>(std::max(0, static_cast<int>(fstorage[name])));
    _learning_stats.assign(_templates.size(), {});
    for (size_t template_idx = _anchor_count; template_idx < _templates.size(); ++template_idx) {
        const auto suffix = std::to_string(idx) + "_"s + std::to_string(template_idx);
        auto& stats = _learning_stats[template_idx];
        const auto hits = fstorage["learned_hits"s + suffix];
        const auto opportunities = fstorage["learned_opportunities"s + suffix];
        const auto sequence = fstorage["learned_sequence"s + suffix];
        if (not hits.empty()) stats.hits = std::max(0, static_cast<int>(hits));
        if (not opportunities.empty()) stats.opportunities = std::max(0, static_cast<int>(opportunities));
        if (not sequence.empty()) stats.sequence = std::max(0, static_cast<int>(sequence));
    }
    _pending_template.release();
    _unsaved_usage = 0;
}
    
void FingerprintStorage::load()
{
    _fingerprints.clear();

    std::filesystem::path filename{_filename};

    if (not std::filesystem::exists(filename)) {
        return;
    }

    size_t filesize = std::filesystem::file_size(filename);

    if (filesize <= 16) {
        return;
    }

    std::vector<unsigned char> encrypted{};
    encrypted.resize(filesize);

    FILE* file = fopen(_filename.c_str(), "rb");
    if (file == nullptr) {
        return;
    }
    // Check the read actually succeeded - a short read left the buffer partly
    // uninitialised and was then handed to the AEAD decrypt.
    bool read_ok = fread(encrypted.data(), encrypted.size(), 1, file) == 1;
    fclose(file);
    if (not read_ok) {
        jinx_log_error() << "read " << _filename << " failed or truncated";
        return;
    }

    const bool new_format = encrypted.size() >= STORAGE_MAGIC.size() + STORAGE_NONCE_SIZE + 16 and
        std::equal(STORAGE_MAGIC.begin(), STORAGE_MAGIC.end(), encrypted.begin());
    const size_t payload_offset = new_format ? STORAGE_MAGIC.size() + STORAGE_NONCE_SIZE : 0;
    std::vector<unsigned char> data(encrypted.size() - payload_offset - 16);
    jinx::SliceConst key{_key.data(), _key.size()};
    jinx::SliceConst nonce{
        new_format ? encrypted.data() + STORAGE_MAGIC.size() : _key.data(),
        STORAGE_NONCE_SIZE};

    auto ret = crypto::decrypt(
        EVP_chacha20_poly1305(), 
        key, 
        nonce, 
        key, 
        {encrypted.data() + payload_offset, data.size()},
        {data.data(), data.size()}, 
        {encrypted.data() + encrypted.size() - 16, 16});

    if (not ret) {
        return;
    }

    std::string data_string{reinterpret_cast<char*>(data.data()), data.size()};
    cv::FileStorage fstorage{data_string, cv::FileStorage::READ | cv::FileStorage::MEMORY | cv::FileStorage::FORMAT_JSON};

    auto count = (int)fstorage["count"];

    for (int idx = 0 ; idx < count; ++idx) {
        Fingerprint print{};
        print.read(fstorage, idx);
        insert_or_update(std::move(print));
    }
}

bool FingerprintStorage::save()
{
    cv::FileStorage fstorage{"memory", cv::FileStorage::WRITE | cv::FileStorage::MEMORY | cv::FileStorage::FORMAT_JSON};
    int count = 0;
    std::string name{};
    for (auto& user : _fingerprints) {
        for (auto& print : user.second) {
            print.second.write(fstorage, count);
            ++ count;
        }
    }
    fstorage.write("count", count);

    auto data = fstorage.releaseAndGetString();

    std::vector<unsigned char> encrypted{};
    const size_t payload_offset = STORAGE_MAGIC.size() + STORAGE_NONCE_SIZE;
    encrypted.resize(payload_offset + data.size() + 16);
    std::copy(STORAGE_MAGIC.begin(), STORAGE_MAGIC.end(), encrypted.begin());
    if (RAND_bytes(encrypted.data() + STORAGE_MAGIC.size(), STORAGE_NONCE_SIZE) != 1) {
        jinx_log_error() << "random fingerprint database nonce failed";
        return false;
    }

    jinx::SliceConst key{_key.data(), _key.size()};
    jinx::SliceConst nonce{encrypted.data() + STORAGE_MAGIC.size(), STORAGE_NONCE_SIZE};

    if (not crypto::encrypt(
        EVP_chacha20_poly1305(), 
        key, 
        nonce, 
        key, 
        {data.data(), 
        data.size()}, 
        {encrypted.data() + payload_offset, data.size()},
        {encrypted.data() + payload_offset + data.size(), 16})) {
        jinx_log_error() << "encrypt fingerprint database failed";
        return false;
    }

    // Write atomically: serialise to a temporary file, fsync it, then rename
    // over the real one. The original opened the live database with "wb", which
    // truncates in place - a crash or power loss mid-write left a truncated
    // file, i.e. every enrolled fingerprint for every user silently lost.
    // rename(2) within the same directory is atomic, so the database is either
    // the old version or the new one, never a partial write.
    std::string tmp_filename = _filename + ".tmp";

    FILE* file = fopen(tmp_filename.c_str(), "wb");
    if (file == nullptr) {
        // The original logged this and then called fwrite/fclose on the null
        // pointer, crashing the daemon on any write failure (read-only mount,
        // full disk, bad permissions).
        jinx_log_error() << "write " << tmp_filename << " failed: " << strerror(errno);
        return false;
    }

    bool ok = fwrite(encrypted.data(), encrypted.size(), 1, file) == 1;
    if (not ok) {
        jinx_log_error() << "write " << tmp_filename << " failed: " << strerror(errno);
    }

    // Force to disk before the rename, otherwise the rename can land while the
    // contents are still only in the page cache.
    if (ok and (fflush(file) != 0 or fsync(fileno(file)) != 0)) {
        jinx_log_error() << "fsync " << tmp_filename << " failed: " << strerror(errno);
        ok = false;
    }

    if (fclose(file) != 0 and ok) {
        jinx_log_error() << "close " << tmp_filename << " failed: " << strerror(errno);
        ok = false;
    }

    if (not ok) {
        ::unlink(tmp_filename.c_str());
        return false;
    }

    // Match the intended 0600 before the file becomes the live database, so
    // there is no window where it is readable by others.
    if (::chmod(tmp_filename.c_str(), S_IRUSR | S_IWUSR) != 0) {
        jinx_log_error() << "chmod " << tmp_filename << " failed: " << strerror(errno);
        ::unlink(tmp_filename.c_str());
        return false;
    }

    if (::rename(tmp_filename.c_str(), _filename.c_str()) != 0) {
        jinx_log_error() << "rename to " << _filename << " failed: " << strerror(errno);
        ::unlink(tmp_filename.c_str());
        return false;
    }
    return true;
}

void FingerprintStorage::init(const std::string &filename, const std::vector<unsigned char>& key)
{
    assert(key.size() == 32);
    _filename = filename;
    _key = key;
    load();
}

void FingerprintStorage::insert_or_update(Fingerprint&& fingerprint)
{
    std::string name = fingerprint._name;
    auto user = _fingerprints.find(fingerprint._user);
    if (user == _fingerprints.end()) {
        auto pair = _fingerprints.emplace(fingerprint._user, std::unordered_map<std::string, Fingerprint>{});
        pair.first->second.emplace(name, std::move(fingerprint));
        return;
    }
    auto print = user->second.find(name);
    if (print == user->second.end()) {
        user->second.emplace(name, std::move(fingerprint));
    } else {
        print->second = std::move(fingerprint);
    }
}

Fingerprint* FingerprintStorage::unique_strong_anchor(
    const std::string& username, const cv::Mat& img)
{
    Fingerprint* found = nullptr;
    bool ambiguous = false;
    foreach(username, [&](Fingerprint& print) {
        if (print.strong_anchor_match(img)) {
            if (found != nullptr) {
                ambiguous = true;
                return true;
            }
            found = &print;
        }
        return false;
    });
    return ambiguous ? nullptr : found;
}

bool FingerprintStorage::update_after_verification(
    Fingerprint& fingerprint, const cv::Mat& img, bool unique_anchor)
{
    Fingerprint before = fingerprint;
    try {
        if (fingerprint.observe_verified_scan(img, unique_anchor)) {
            if (not save()) {
                fingerprint = std::move(before);
                return false;
            }
            fingerprint.usage_saved();
            return true;
        }
        if (fingerprint.usage_save_due() and save()) {
            fingerprint.usage_saved();
        }
    } catch (const std::exception& exc) {
        fingerprint = std::move(before);
        jinx_log_error() << "adaptive fingerprint update failed: " << exc.what();
    }
    return false;
}

}
