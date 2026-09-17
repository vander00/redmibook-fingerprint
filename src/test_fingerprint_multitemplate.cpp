#include <cstdlib>
#include <cmath>
#include <iostream>
#include <string>

#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>

#include "drv_fpc/fingerprint.hpp"

namespace {

[[noreturn]] void fail(const char* message)
{
    std::cerr << "FAIL: " << message << std::endl;
    std::exit(1);
}

void require(bool condition, const char* message)
{
    if (not condition) {
        fail(message);
    }
}

cv::Mat make_pattern(uint64_t seed)
{
    cv::Mat image{cv::Size{224, 176}, CV_8UC1, cv::Scalar{24}};
    cv::RNG rng{seed};

    // Deterministic ridge-like arcs plus small features give SIFT enough
    // structure without depending on private fingerprint captures.
    for (int radius = 16; radius < 150; radius += 7) {
        cv::ellipse(
            image,
            cv::Point{112 + rng.uniform(-3, 4), 120 + rng.uniform(-3, 4)},
            cv::Size{radius, std::max(8, radius / 2)},
            rng.uniform(-8.0, 8.0),
            190.0,
            350.0,
            cv::Scalar{static_cast<double>(150 + rng.uniform(0, 90))},
            2,
            cv::LINE_AA);
    }
    for (int idx = 0; idx < 35; ++idx) {
        cv::circle(
            image,
            cv::Point{rng.uniform(15, 209), rng.uniform(15, 161)},
            rng.uniform(1, 4),
            cv::Scalar{static_cast<double>(rng.uniform(80, 255))},
            -1,
            cv::LINE_AA);
    }
    return image;
}

cv::Mat reposition(const cv::Mat& image, double angle, double x, double y)
{
    const double radians = angle * CV_PI / 180.0;
    const double alpha = std::cos(radians);
    const double beta = std::sin(radians);
    const double center_x = image.cols / 2.0;
    const double center_y = image.rows / 2.0;
    cv::Mat matrix(2, 3, CV_64F);
    matrix.at<double>(0, 0) = alpha;
    matrix.at<double>(0, 1) = beta;
    matrix.at<double>(0, 2) = (1.0 - alpha) * center_x - beta * center_y + x;
    matrix.at<double>(1, 0) = -beta;
    matrix.at<double>(1, 1) = alpha;
    matrix.at<double>(1, 2) = beta * center_x + (1.0 - alpha) * center_y + y;

    cv::Mat output{};
    cv::warpAffine(image, output, matrix, image.size(), cv::INTER_LINEAR,
                   cv::BORDER_CONSTANT, cv::Scalar{24});
    return output;
}

} // namespace

int main()
{
    const auto enrolled = make_pattern(0x9201);
    const auto right = reposition(enrolled, 1.0, 30.0, 0.0);
    const auto left = reposition(enrolled, -1.0, -30.0, 0.0);
    const auto down = reposition(enrolled, 1.0, 0.0, 28.0);
    const auto up = reposition(enrolled, -1.0, 0.0, -28.0);
    const auto nearby_right = reposition(right, 2.0, 5.0, -4.0);
    const auto angled = reposition(enrolled, 3.0, 3.0, -2.0);
    const auto angled_other_way = reposition(enrolled, -3.0, -2.0, 3.0);
    const auto nearby_left = reposition(left, 2.0, 4.0, 2.0);
    cv::Mat lighter{};
    enrolled.convertTo(lighter, CV_8UC1, 0.90, 8.0);
    const auto other = make_pattern(0x10a5);

    fpc::Fingerprint fingerprint{};
    fingerprint._user = "test-user";
    fingerprint._name = "right-index-finger";

    require(fingerprint.merge(enrolled) == fpc::EnrollmentSampleResult::accepted,
            "first enrollment frame rejected");
    const auto first_area = fingerprint.total();
    require(fingerprint.merge(enrolled) == fpc::EnrollmentSampleResult::insufficient_new_area,
            "duplicate enrollment position accepted");
    require(fingerprint.template_count() == 1, "duplicate position advanced enrollment");
    require(fingerprint.total() == first_area, "duplicate position changed stitched coverage");
    require(fingerprint.merge(right) == fpc::EnrollmentSampleResult::accepted,
            "right enrollment position rejected");
    require(fingerprint.merge(left) == fpc::EnrollmentSampleResult::accepted,
            "left enrollment position rejected");
    require(fingerprint.merge(down) == fpc::EnrollmentSampleResult::accepted,
            "lower enrollment position rejected");
    require(fingerprint.merge(up) == fpc::EnrollmentSampleResult::accepted,
            "upper enrollment position rejected");
    require(fingerprint.template_count() == fpc::DISTINCT_AREA_POSITION_TEMPLATES,
            "distinct-area positions not retained");

    // Once coverage has been built, alignable placements are valuable even
    // when they add less than 10% new area.
    require(fingerprint.merge(enrolled) == fpc::EnrollmentSampleResult::accepted,
            "duplicate variation rejected after coverage phase");
    require(fingerprint.merge(nearby_right) == fpc::EnrollmentSampleResult::accepted,
            "nearby right variation rejected");
    require(fingerprint.merge(nearby_left) == fpc::EnrollmentSampleResult::accepted,
            "nearby left variation rejected");
    require(fingerprint.merge(angled) == fpc::EnrollmentSampleResult::accepted,
            "angled variation rejected");
    require(fingerprint.merge(lighter) == fpc::EnrollmentSampleResult::accepted,
            "pressure variation rejected");
    require(fingerprint.template_count() == fpc::MAX_POSITION_TEMPLATES,
            "ten position templates not retained");
    require(fingerprint.match(enrolled, 0.30F, 0.40F, false), "center position did not match");
    require(fingerprint.match(right, 0.30F, 0.40F, false), "right position did not match");
    require(fingerprint.match(left, 0.30F, 0.40F, false), "left position did not match");
    require(fingerprint.match(down, 0.30F, 0.40F, false), "lower position did not match");
    require(fingerprint.match(up, 0.30F, 0.40F, false), "upper position did not match");
    require(fingerprint.match(nearby_right, 0.30F, 0.40F, false),
            "nearby variation of known position did not match");
    require(fingerprint.match(angled_other_way, 0.30F, 0.40F, false),
            "varied angle did not match");
    require(fingerprint.match(lighter, 0.30F, 0.40F, false),
            "varied pressure did not match");
    require(not fingerprint.match(other, 0.30F, 0.40F, false), "unrelated pattern matched");

    const auto completed_area = fingerprint.total();
    require(fingerprint.merge(other) == fpc::EnrollmentSampleResult::unmatchable,
            "unrelated sample accepted after coverage phase");
    require(fingerprint.template_count() == fpc::MAX_POSITION_TEMPLATES,
            "failed post-coverage sample changed template count");
    require(fingerprint.total() == completed_area,
            "failed post-coverage sample changed stitched coverage");

    fpc::Fingerprint rejected{};
    require(rejected.merge(enrolled) == fpc::EnrollmentSampleResult::accepted,
            "rejection fixture was not initialized");
    const auto accepted_area = rejected.total();
    require(rejected.merge(other) == fpc::EnrollmentSampleResult::unmatchable,
            "unrelated enrollment sample was accepted");
    require(rejected.template_count() == 1, "unmatchable sample advanced enrollment");
    require(rejected.total() == accepted_area, "unmatchable sample changed stitched coverage");

    cv::FileStorage writer{
        "memory", cv::FileStorage::WRITE | cv::FileStorage::MEMORY |
                      cv::FileStorage::FORMAT_JSON};
    fingerprint.write(writer, 0);
    const auto serialized = writer.releaseAndGetString();

    cv::FileStorage reader{
        serialized, cv::FileStorage::READ | cv::FileStorage::MEMORY |
                        cv::FileStorage::FORMAT_JSON};
    fpc::Fingerprint restored{};
    restored.read(reader, 0);
    require(restored.template_count() == fpc::MAX_POSITION_TEMPLATES,
            "position templates lost on reload");
    require(restored.match(nearby_right, 0.30F, 0.40F, false),
            "reloaded template did not match");

    // Records written by the previous five-position release remain readable.
    fpc::Fingerprint five_template_record{};
    require(five_template_record.merge(enrolled) == fpc::EnrollmentSampleResult::accepted,
            "five-template fixture initialization failed");
    require(five_template_record.merge(right) == fpc::EnrollmentSampleResult::accepted,
            "five-template fixture right position failed");
    require(five_template_record.merge(left) == fpc::EnrollmentSampleResult::accepted,
            "five-template fixture left position failed");
    require(five_template_record.merge(down) == fpc::EnrollmentSampleResult::accepted,
            "five-template fixture lower position failed");
    require(five_template_record.merge(up) == fpc::EnrollmentSampleResult::accepted,
            "five-template fixture upper position failed");
    cv::FileStorage five_writer{
        "memory", cv::FileStorage::WRITE | cv::FileStorage::MEMORY |
                      cv::FileStorage::FORMAT_JSON};
    five_template_record.write(five_writer, 0);
    const auto five_serialized = five_writer.releaseAndGetString();
    cv::FileStorage five_reader{
        five_serialized, cv::FileStorage::READ | cv::FileStorage::MEMORY |
                             cv::FileStorage::FORMAT_JSON};
    fpc::Fingerprint five_restored{};
    five_restored.read(five_reader, 0);
    require(five_restored.template_count() == fpc::DISTINCT_AREA_POSITION_TEMPLATES,
            "five-template record did not retain all templates");
    require(five_restored.match(up, 0.30F, 0.40F, false),
            "five-template record stopped matching");

    // An old database has only print/mask. It must remain usable after upgrade.
    cv::Mat legacy_mask{enrolled.size(), CV_32F, cv::Scalar{1.0F}};
    cv::FileStorage legacy_writer{
        "memory", cv::FileStorage::WRITE | cv::FileStorage::MEMORY |
                      cv::FileStorage::FORMAT_JSON};
    legacy_writer << "user0" << "test-user";
    legacy_writer << "name0" << "right-index-finger";
    legacy_writer << "print0" << enrolled;
    legacy_writer << "mask0" << legacy_mask;
    const auto legacy_serialized = legacy_writer.releaseAndGetString();

    cv::FileStorage legacy_reader{
        legacy_serialized, cv::FileStorage::READ | cv::FileStorage::MEMORY |
                               cv::FileStorage::FORMAT_JSON};
    fpc::Fingerprint legacy{};
    legacy.read(legacy_reader, 0);
    require(legacy.template_count() == 0, "legacy record gained synthetic templates");
    require(legacy.match(nearby_right, 0.30F, 0.40F, false),
            "legacy template stopped matching");

    std::cout << "PASS: ten-template matching and compatible storage" << std::endl;
    return 0;
}
