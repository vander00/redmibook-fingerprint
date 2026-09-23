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
#include <iostream>
#include <algorithm>
#include <cmath>
#include <opencv2/features2d.hpp>
#include <opencv2/calib3d.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/highgui.hpp>

#include "cvext.hpp"

namespace cvext {

bool match_impl(const cv::Mat& fingerprint, const cv::Mat& fp_mask, const cv::Mat& partial, int min_match, double min_score, bool filter, double min_overlap_ratio, double* overlap_ratio);
bool merge_impl(const cv::Mat& img1, const cv::Mat& mask1, const cv::Mat& img2, cv::Mat& output, cv::Mat& output_mask);

// Reject homographies that are geometrically implausible for a finger press on
// a small area sensor. Loosening the ratio test below lets more (and noisier)
// correspondences through, so we compensate here to keep false accepts down.
static bool homography_is_sane(const cv::Mat& hmat)
{
    if (hmat.empty() or hmat.type() != CV_64F or hmat.rows != 3 or hmat.cols != 3) {
        return false;
    }

    for (int row = 0; row < 3; ++row) {
        for (int col = 0; col < 3; ++col) {
            if (not std::isfinite(hmat.at<double>(row, col))) {
                return false;
            }
        }
    }

    // Normalise so h22 == 1, then inspect the affine part.
    double h22 = hmat.at<double>(2, 2);
    if (std::abs(h22) < 1e-9) {
        return false;
    }

    double a11 = hmat.at<double>(0, 0) / h22;
    double a12 = hmat.at<double>(0, 1) / h22;
    double a21 = hmat.at<double>(1, 0) / h22;
    double a22 = hmat.at<double>(1, 1) / h22;

    // Determinant of the linear part == area scaling. A genuine re-press of the
    // same finger is near 1.0. The sensor is fixed size, so a real sample
    // cannot legitimately need a 2x stretch to line up - observed bogus
    // alignments scored ~0.07 while stretching ~2x, so keep this tight.
    double det = (a11 * a22) - (a12 * a21);
    if (std::abs(det) < 0.64 or std::abs(det) > 1.5625) {
        return false;
    }

    // Perspective terms must stay small - the sensor is flat, so a real press
    // is essentially a rotation + translation, not a strong projective warp.
    double p20 = hmat.at<double>(2, 0) / h22;
    double p21 = hmat.at<double>(2, 1) / h22;
    if (std::abs(p20) > 0.01 or std::abs(p21) > 0.01) {
        return false;
    }

    return true;
}

bool get_transform_matrix(const cv::Mat& img1, const cv::Mat& img2, cv::Mat& output, int min_match, cv::Point offset={0, 0})
{
    assert(img1.type() == CV_8UC1);
    assert(img2.type() == CV_8UC1);

    if (img1.empty() or img2.empty()) {
        return false;
    }

    auto sift = cv::SIFT::create();
    
    std::vector<cv::KeyPoint> keypoints1{};
    std::vector<cv::KeyPoint> keypoints2{};
    cv::Mat descriptors1{};
    cv::Mat descriptors2{};

    sift->detectAndCompute(img1, {}, keypoints1, descriptors1);
    sift->detectAndCompute(img2, {}, keypoints2, descriptors2);

    // knnMatch(k=2) needs at least 2 train descriptors, and throws on empty
    // input. A worn or badly placed finger really does produce this.
    if (descriptors1.empty() or descriptors2.rows < 2) {
        return false;
    }

    std::vector<cv::Point2f> points1{};
    std::vector<cv::Point2f> points2{};

    std::for_each(keypoints1.begin(), keypoints1.end(), [&](cv::KeyPoint& keypoint){
        points1.push_back(keypoint.pt);
    });

    std::for_each(keypoints2.begin(), keypoints2.end(), [&](cv::KeyPoint& keypoint){
        points2.push_back(keypoint.pt);
    });

    auto bf_matcher = cv::BFMatcher::create();
    std::vector<std::vector<cv::DMatch>> matches{};
    bf_matcher->knnMatch(descriptors1, descriptors2, matches, 2);

    // Lowe ratio test. The original 0.6 is very strict: on a degraded or
    // partially-placed print it discards most true correspondences and the
    // match fails outright. 0.75 is Lowe's own recommendation; the RANSAC
    // inlier count and homography sanity check below filter the extra noise.
    constexpr float kRatio = 0.75F;

    std::vector<cv::Point2f> good_points1{};
    std::vector<cv::Point2f> good_points2{};

    for(auto& vpair : matches) {
        if (vpair.size() < 2) {
            continue;
        }
        auto& match1 = vpair.at(0);
        auto& match2 = vpair.at(1);

        if (match1.distance < (kRatio * match2.distance)) {
            if (match1.queryIdx < 0 or match1.queryIdx >= (int)points1.size() or
                match1.trainIdx < 0 or match1.trainIdx >= (int)points2.size()) {
                continue;
            }
            good_points1.push_back(points1[match1.queryIdx] + cv::Point2f(offset));
            good_points2.push_back(points2[match1.trainIdx]);
        }
    }

    if ((int)good_points1.size() < min_match) {
        return false;
    }

    cv::Mat inliers{};
    output = cv::findHomography(good_points2, good_points1, cv::RANSAC, 4, inliers);

    if (not homography_is_sane(output)) {
        output.release();
        return false;
    }

    // Require the homography to actually be supported by enough points, not
    // just be computable from the 4-point minimum.
    if (not inliers.empty() and cv::countNonZero(inliers) < min_match) {
        output.release();
        return false;
    }

    return true;
}

cv::Mat garbor_filter(
    cv::Mat& img, 
    size_t ksize=16, 
    double sigma=3.0, 
    size_t filter_max=8, 
    double lambd=10.0, 
    double gamma=0.5)
{
    std::array<cv::Mat, 8> filters{};
    double theta = 0.0;
    for (auto& mat : filters) {
        auto kernel = cv::getGaborKernel(cv::Size(ksize, ksize), sigma, theta, lambd, gamma, 0, CV_32F);
        cv::divide(kernel, cv::sum(kernel), mat);
        theta += CV_PI / filters.size();
    }

    cv::Mat output = cv::Mat::zeros(img.size(), img.type());

    for (auto& mat : filters) {
        cv::Mat new_image;
        cv::filter2D(img, new_image, -1, mat);
        cv::max(output, new_image, output);
    }
    return output;
}

void get_orientation(cv::Mat& img, cv::Mat& magnitude, cv::Mat& angle)
{
    cv::Mat grad1{};
    cv::Mat grad2{};

    cv::Sobel(img, grad1, CV_32F, 1, 0);
    cv::Sobel(img, grad2, CV_32F, 0, 1);

    cv::cartToPolar(grad1, grad2, magnitude, angle);
}

cv::Mat garbor_filter_orientation(
    cv::Mat& img,
    double sigma=3.5, 
    size_t filter_max=8, 
    double lambd=10.0, 
    double gamma=0.5)
{
    cv::Mat magnitude{};
    cv::Mat angle{};

    get_orientation(img, magnitude, angle);

    cv::subtract(angle, CV_PI, angle, angle>=CV_PI);

    auto mid = cv::mean(magnitude);
    auto theta = cv::mean(angle, magnitude > mid)[0];

    auto kernel = cv::getGaborKernel(img.size(), sigma, theta, lambd, gamma, 0, CV_32F);
    cv::divide(kernel, cv::sum(kernel), kernel);

    cv::Mat new_image;
    cv::filter2D(img, new_image, -1, kernel);
    return new_image;
}

cv::Mat garbor_filter_block_wise(
    cv::Mat& img,
    size_t block_size,
    size_t overlap,
    double sigma=3.5, 
    size_t filter_max=8, 
    double lambd=10.0, 
    double gamma=0.5
) {
    auto size = img.size();
    auto width = ((size.width + block_size - 1) / block_size) * block_size;
    auto height = ((size.height + block_size - 1) / block_size) * block_size;
    cv::Mat new_img{img.size(), img.type()};

    for (size_t row = 0; row < height; row += overlap) {
        size_t row2 = (row + block_size) > size.height ? size.height - block_size : row;
        for (size_t col = 0; col < width; col += overlap) {
            size_t col2 = (col + block_size) > size.width ? size.width - block_size : col;
            auto block = img(cv::Range(row2, row2 + block_size), cv::Range(col2, col2 + block_size));
            cv::Mat block_eq{};
            cv::equalizeHist(block, block_eq);
            auto block_g = garbor_filter_orientation(block, sigma, filter_max, lambd, gamma);
            block_g.copyTo(new_img(cv::Range(row2, row2 + block_size), cv::Range(col2, col2 + block_size)));
        }
    }
    return new_img;
}

// see https://docs.opencv.org/4.x/d5/dc4/tutorial_video_input_psnr_ssim.html
cv::Scalar MSSIM(cv::Mat& img1, cv::Mat& img2, cv::InputArray mask)
{
    const double C1 = 6.5025;
    const double C2 = 58.5225;

    cv::Mat img1_32f{};
    cv::Mat img2_32f{};

    img1.convertTo(img1_32f, CV_32F);
    img2.convertTo(img2_32f, CV_32F);

    cv::Mat img1_2 = img1_32f.mul(img1_32f);
    cv::Mat img2_2 = img2_32f.mul(img2_32f);
    cv::Mat img12 = img1_32f.mul(img2_32f);

    cv::Mat mu1{};
    cv::Mat mu2{};

    cv::GaussianBlur(img1_32f, mu1, { 11, 11 }, 1.5);
    cv::GaussianBlur(img2_32f, mu2, { 11, 11 }, 1.5);

    cv::Mat mu1_2 = mu1.mul(mu1);
    cv::Mat mu2_2 = mu2.mul(mu2);
    cv::Mat mu12 = mu1.mul(mu2);

    cv::Mat sigma1_2{};
    cv::Mat sigma2_2{};
    cv::Mat sigma12{};

    cv::GaussianBlur(img1_2, sigma1_2, { 11, 11 }, 1.5);
    cv::GaussianBlur(img2_2, sigma2_2, { 11, 11 }, 1.5);
    cv::GaussianBlur(img12, sigma12, { 11, 11 }, 1.5);

    sigma1_2 -= mu1_2;
    sigma2_2 -= mu2_2;
    sigma12 -= mu12;

    auto t1 = 2.0 * img12 + C1;
    auto t2 = 2.0 * sigma12 + C2;
    auto t3 = t1.mul(t2);

    t1 = img1_2 + img2_2 + C1;
    t2 = sigma1_2 + sigma2_2 + C2;
    t1 = t1.mul(t2);

    cv::Mat ssim_map{};
    cv::divide(t3, t1, ssim_map);

    return cv::mean(ssim_map, mask);
}

bool match_impl(const cv::Mat& fingerprint, const cv::Mat& fp_mask, const cv::Mat& partial, int min_match, double min_score, bool filter, double min_overlap_ratio, double* overlap_ratio)
{
    if (fingerprint.empty() or fp_mask.empty() or partial.empty()) {
        return false;
    }

    cv::Mat matrix{};

    auto ret = cvext::get_transform_matrix(fingerprint, partial, matrix, min_match);
    if (not ret) {
        return  false;
    }
    
    cv::Mat shadow{partial.size(), CV_32F};
    shadow.setTo(1.0F);

    cv::Mat dst_img{};
    cv::Mat dst_mask{};

    cv::warpPerspective(partial, dst_img, matrix, fingerprint.size());
    cv::warpPerspective(shadow, dst_mask, matrix, fingerprint.size());

    dst_mask.setTo(0.0F, fp_mask==0);

    cv::Mat valid = dst_mask > 0;

    // The score is a mean over the overlapping region only. If that region is
    // tiny, the mean is statistically meaningless and can clear min_score by
    // luck - which is both a false-accept risk and a source of flaky results.
    // Demand a real overlap before trusting the score.
    const int overlap_px = cv::countNonZero(valid);
    const int min_overlap_px = overlap_ratio == nullptr
        ? static_cast<int>(partial.total() / 4)
        : static_cast<int>(std::ceil(partial.total() * min_overlap_ratio));
    if (overlap_px < min_overlap_px) {
        return false;
    }

    cv::Mat fpr{};
    fingerprint.copyTo(fpr, valid);

    cv::Scalar score{};

    if (filter) {
        auto fpr_g = cvext::garbor_filter_block_wise(fpr, 32, 24);
        auto dst_g = cvext::garbor_filter_block_wise(dst_img, 32, 24);

        score = MSSIM(fpr_g, dst_g, valid);

    } else {
        score = MSSIM(fpr, dst_img, valid);
    }

    // Log the actual score and overlap so thresholds can be tuned against real
    // samples instead of guessed at.
    std::cout << "match: score=" << score[0]
              << " min_score=" << min_score
              << " overlap=" << overlap_px
              << "/" << partial.total()
              << std::endl;

    if (score[0] < min_score) {
        return false;
    }
    if (overlap_ratio != nullptr) {
        *overlap_ratio = static_cast<double>(overlap_px) / partial.total();
    }
    return true;
}

bool merge_impl(const cv::Mat& img1, const cv::Mat& mask1, const cv::Mat& img2, cv::Mat& output, cv::Mat& output_mask)
{
    if (img1.empty() or mask1.empty() or img2.empty()) {
        return false;
    }

    cv::Mat matrix{};

    auto offset = cv::Point(img2.size());
    
    auto ret = get_transform_matrix(img1, img2, matrix, 4, offset);
    if (not ret) {
        return false;
    }

    cv::Size dst_size = img1.size() + img2.size() * 2;

    // process img1
    cv::Mat new_img1 = cv::Mat::zeros(dst_size, img1.type());
    cv::Mat weights1{dst_size, CV_32FC1};
    weights1.setTo(0.0F);
    
    img1.copyTo(new_img1({offset.y, offset.y + img1.rows}, {offset.x, offset.x + img1.cols}));
    mask1.copyTo(weights1({offset.y, offset.y + img1.rows}, {offset.x, offset.x + img1.cols}));

    // generate mask2
    cv::Mat img2_shadow{img2.size(), CV_32FC1};
    img2_shadow.setTo(1.0F);
    
    cv::Mat weights2;
    cv::warpPerspective(img2_shadow, weights2, matrix, dst_size);
    weights2.setTo(0.0F, weights2 < 1.0F);

    // transform img2
    cv::Mat new_img2{};
    cv::warpPerspective(img2, new_img2, matrix, dst_size);

    // blend
    cv::Mat overlap{};
    cv::add(weights1, weights2, overlap);

    auto score = MSSIM(new_img1, new_img2, overlap == 2)[0];
    if (score < 0.3) {
        return false;
    }

    weights1.setTo(0.9F, overlap == 2);
    weights2.setTo(0.1F, overlap == 2);

    cv::blendLinear(new_img1, new_img2, weights1, weights2, new_img1);

    // merge mask
    cv::add(weights1, weights2, weights1);

    // resize
    cv::Vec2f data[] = {
        {0.0F, 0.0F},
        {0.0F, (float)img2.rows},
        {(float)img2.cols, (float)img2.rows},
        {(float)img2.cols, 0.0F} 
    };

    cv::Mat corners{cv::Size(1,4), CV_32FC2, data};

    cv::Mat transformed_corners{};
    cv::perspectiveTransform(corners, transformed_corners, matrix);

    auto left = std::min(transformed_corners.at<float>(0, 0), 
        std::min(transformed_corners.at<float>(1, 0), 
        std::min(transformed_corners.at<float>(2, 0), 
        transformed_corners.at<float>(3, 0))));
    auto top = std::min(transformed_corners.at<float>(0, 1), 
        std::min(transformed_corners.at<float>(1, 1), 
        std::min(transformed_corners.at<float>(2, 1), 
        transformed_corners.at<float>(3, 1))));
    auto right = std::max(transformed_corners.at<float>(0, 0), 
        std::max(transformed_corners.at<float>(1, 0), 
        std::max(transformed_corners.at<float>(2, 0), 
        transformed_corners.at<float>(3, 0))));
    auto bottom = std::max(transformed_corners.at<float>(0, 1), 
        std::max(transformed_corners.at<float>(1, 1), 
        std::max(transformed_corners.at<float>(2, 1), 
        transformed_corners.at<float>(3, 1))));

    auto left1 = offset.x;
    auto top1 = offset.y;
    auto right1 = offset.x + img1.cols;
    auto bottom1 = offset.y + img1.rows;
    if (left < left1) {
        left1 = left;
    }
    if (right > right1) {
        right1 = right;
    }
    if (top < top1) {
        top1 = top;
    }
    if (bottom > bottom1) {
        bottom1 = bottom;
    }

    // The warped corners can land outside the canvas (a rotated press near the
    // sensor edge does this readily). cv::Range would then throw and, before
    // the abort() fix, take the daemon with it. Clamp to the canvas instead so
    // an off-angle sample is merged on its valid part rather than lost.
    left1 = std::max(0, std::min<int>(left1, new_img1.cols - 1));
    top1 = std::max(0, std::min<int>(top1, new_img1.rows - 1));
    right1 = std::max(left1 + 1, std::min<int>(right1, new_img1.cols));
    bottom1 = std::max(top1 + 1, std::min<int>(bottom1, new_img1.rows));

    output = new_img1(cv::Range{top1, bottom1}, cv::Range{left1, right1});
    output_mask = weights1(cv::Range{top1, bottom1}, cv::Range{left1, right1});
    return true;
}

// Public entry points. OpenCV signals errors by throwing cv::Exception, and
// these run inside the daemon's single-threaded event loop, so one bad sample
// escaping as an exception terminates fingerpp (and logs the user out of
// fingerprint auth entirely). A failed match/merge is a normal, expected
// outcome for a smudged or off-angle press: report it as false and let the
// caller ask for another scan.
bool match(const cv::Mat& fingerprint, const cv::Mat& fp_mask, const cv::Mat& partial, int min_match, double min_score, bool filter)
{
    try {
        return match_impl(fingerprint, fp_mask, partial, min_match, min_score, filter, 0.25, nullptr);
    } catch (const cv::Exception& exc) {
        std::cerr << "match: opencv error: " << exc.what() << std::endl;
        return false;
    } catch (const std::exception& exc) {
        std::cerr << "match: error: " << exc.what() << std::endl;
        return false;
    }
}

bool enrollment_match(const cv::Mat& fingerprint, const cv::Mat& partial, double& overlap_ratio)
{
    try {
        if (fingerprint.empty() or partial.empty()) {
            return false;
        }
        cv::Mat mask{fingerprint.size(), CV_32F, cv::Scalar{1.0F}};
        return match_impl(fingerprint, mask, partial, 6, 0.4, false, 0.15, &overlap_ratio);
    } catch (const cv::Exception& exc) {
        std::cerr << "enrollment match: opencv error: " << exc.what() << std::endl;
        return false;
    } catch (const std::exception& exc) {
        std::cerr << "enrollment match: error: " << exc.what() << std::endl;
        return false;
    }
}

bool has_enrollment_features(const cv::Mat& image)
{
    if (image.empty() or image.type() != CV_8UC1) {
        return false;
    }
    try {
        std::vector<cv::KeyPoint> keypoints{};
        cv::SIFT::create()->detect(image, keypoints);
        return keypoints.size() >= 6;
    } catch (const cv::Exception& exc) {
        std::cerr << "enrollment features: opencv error: " << exc.what() << std::endl;
        return false;
    }
}

bool merge(const cv::Mat& img1, const cv::Mat& mask1, const cv::Mat& img2, cv::Mat& output, cv::Mat& output_mask)
{
    try {
        return merge_impl(img1, mask1, img2, output, output_mask);
    } catch (const cv::Exception& exc) {
        std::cerr << "merge: opencv error: " << exc.what() << std::endl;
        return false;
    } catch (const std::exception& exc) {
        std::cerr << "merge: error: " << exc.what() << std::endl;
        return false;
    }
}

}
