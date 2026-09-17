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

#include <sys/stat.h>
#include <unistd.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <opencv2/imgproc.hpp>

#include "jinx/logging.hpp"

#include "fingerprint.hpp"
#include "crypto.hpp"

namespace fpc {
using namespace std::string_literals;

EnrollmentSampleResult Fingerprint::merge(const cv::Mat& img)
{
    if (_fingerprint.empty()) {
        _fingerprint = img.clone();
        _mask.create(_fingerprint.size(), CV_32F);
        _mask.setTo(1.0F);
        _templates.push_back(img.clone());
        return EnrollmentSampleResult::accepted;
    }

    cv::Mat output{};
    cv::Mat mask{};
    auto ret = cvext::merge(_fingerprint, _mask, img, output, mask);
    if (not ret) {
        return EnrollmentSampleResult::unmatchable;
    }

    if (_templates.size() < DISTINCT_AREA_POSITION_TEMPLATES) {
        const auto current_area = total();
        const auto candidate_area = static_cast<size_t>(cv::sum(mask)[0]);
        const auto minimum_gain = static_cast<size_t>(
            std::ceil(static_cast<double>(img.total()) * MIN_NEW_POSITION_AREA_RATIO));
        const auto area_gain = candidate_area > current_area ? candidate_area - current_area : 0;
        if (area_gain < minimum_gain) {
            return EnrollmentSampleResult::insufficient_new_area;
        }
    }

    _fingerprint = std::move(output);
    _mask = std::move(mask);
    if (_templates.size() < MAX_POSITION_TEMPLATES) {
        _templates.push_back(img.clone());
    }
    return EnrollmentSampleResult::accepted;
}

bool Fingerprint::match(
    const cv::Mat &img,
    float legacy_min_score,
    float position_min_score,
    bool filter) const
{
    // Position-specific frames avoid forcing every verification press to align
    // against a large stitched canvas. They use the same hardened
    // SIFT/RANSAC/SSIM acceptance path and threshold as the legacy template;
    // unlike PR #8, no uncalibrated classifier can accept a print by itself.
    for (size_t idx = 0; idx < _templates.size(); ++idx) {
        cv::Mat mask{_templates[idx].size(), CV_32F};
        mask.setTo(1.0F);
        if (cvext::match(_templates[idx], mask, img, 4, position_min_score, filter)) {
            std::cout << "match: position-template=" << idx << std::endl;
            return true;
        }
    }

    // Old databases contain only the stitched template. New databases keep it
    // for rollback compatibility, but do not use its lower legacy threshold:
    // trying both paths would multiply false-accept opportunities and defeat
    // the stricter per-position matcher.
    if (_templates.empty()) {
        return cvext::match(_fingerprint, _mask, img, 4, legacy_min_score, filter);
    }
    return false;
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

    for (size_t template_idx = 0; template_idx < _templates.size(); ++template_idx) {
        name = "template"s + std::to_string(idx) + "_"s + std::to_string(template_idx);
        fstorage << name << _templates[template_idx];
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

    std::vector<unsigned char> data{};
    data.resize(filesize - 16);

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

    jinx::SliceConst key{_key.data(), _key.size()};
    jinx::SliceConst nonce{_key.data(), 12};

    auto ret = crypto::decrypt(
        EVP_chacha20_poly1305(), 
        key, 
        nonce, 
        key, 
        {encrypted.data(), encrypted.size() - 16}, 
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

void FingerprintStorage::save()
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
    encrypted.resize(data.size() + 16);

    jinx::SliceConst key{_key.data(), _key.size()};
    jinx::SliceConst nonce{_key.data(), 12};

    crypto::encrypt(
        EVP_chacha20_poly1305(), 
        key, 
        nonce, 
        key, 
        {data.data(), 
        data.size()}, 
        {encrypted.data(), data.size()},
        {encrypted.data() + data.size(), 16});

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
        return;
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
        return;
    }

    // Match the intended 0600 before the file becomes the live database, so
    // there is no window where it is readable by others.
    if (::chmod(tmp_filename.c_str(), S_IRUSR | S_IWUSR) != 0) {
        jinx_log_error() << "chmod " << tmp_filename << " failed: " << strerror(errno);
    }

    if (::rename(tmp_filename.c_str(), _filename.c_str()) != 0) {
        jinx_log_error() << "rename to " << _filename << " failed: " << strerror(errno);
        ::unlink(tmp_filename.c_str());
    }
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

}
