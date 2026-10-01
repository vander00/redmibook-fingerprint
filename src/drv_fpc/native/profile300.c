/* Native profile-300 arithmetic. Original RVAs and evidence: PROVENANCE.md. */
#include "profile300.h"
#include "profile300_tables.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* 0726c0/072c10: radix-four first stage, then radix-two butterflies.
 * Scalar additions retain the instruction order of the original unrolled loops.
 */
static void complex_transform(const float *input, float *output, unsigned n, int inverse) {
    const int16_t *permutation = fpc_fft_permutation + n - 1;
    for (unsigned i = 0; i < n; i += 4) {
        unsigned a = 2 * (unsigned)permutation[i], b = 2 * (unsigned)permutation[i + 1];
        unsigned c = 2 * (unsigned)permutation[i + 2], d = 2 * (unsigned)permutation[i + 3];
        float ar = input[a], ai = input[a + 1], br = input[b], bi = input[b + 1];
        float cr = input[c], ci = input[c + 1], dr = input[d], di = input[d + 1];
        float ab = br + ar, ad = ar - br, ib = bi + ai, id = ai - bi;
        float cd = dr + cr, dd = cr - dr, jb = di + ci, jd = ci - di;
        output[2 * i] = cd + ab;
        output[2 * i + 1] = jb + ib;
        output[2 * i + 2] = inverse ? jd + ad : ad - jd;
        output[2 * i + 3] = inverse ? id - dd : dd + id;
        output[2 * i + 4] = ab - cd;
        output[2 * i + 5] = ib - jb;
        output[2 * i + 6] = inverse ? ad - jd : jd + ad;
        output[2 * i + 7] = inverse ? dd + id : id - dd;
    }
    for (unsigned width = 4, step = 512; width < n; width *= 2, step /= 2) {
        for (unsigned j = 0; j < width; ++j) {
            float cosine = fpc_fft_twiddles[j * step], sine = fpc_fft_twiddles[j * step + 1];
            for (unsigned base = j; base < n; base += 2 * width) {
                unsigned a = 2 * base, b = 2 * (base + width);
                float ar = output[a], ai = output[a + 1], br = output[b], bi = output[b + 1];
                float tr = inverse ? sine * bi + cosine * br : cosine * br - sine * bi;
                float ti = inverse ? cosine * bi - sine * br : cosine * bi + sine * br;
                output[a + 1] = ti + ai;
                output[a] = tr + ar;
                output[b + 1] = ai - ti;
                output[b] = ar - tr;
            }
        }
    }
}

/* 073160/073670: real FFT bridge. */
static void real_forward(float *input, float *output, unsigned n) {
    float temporary[128];
    complex_transform(input, temporary, n / 2, 0);
    unsigned step = 2048 / n;
    for (unsigned k = 1; k < n / 4; ++k) {
        unsigned a = 2 * k, b = n - 2 * k;
        float sum = (temporary[b] + temporary[a]) * 0.5f;
        float diff = (temporary[b] - temporary[a]) * 0.5f;
        float imag_sum = (temporary[b + 1] + temporary[a + 1]) * 0.5f;
        float imag_diff = (temporary[a + 1] - temporary[b + 1]) * 0.5f;
        float cosine = fpc_fft_twiddles[2 * k * step], sine = fpc_fft_twiddles[2 * k * step + 1];
        float tr = imag_sum * cosine - diff * sine;
        float ti = imag_sum * sine + diff * cosine;
        output[a] = tr + sum;
        output[a + 1] = ti + imag_diff;
        output[b + 1] = ti - imag_diff;
        output[b] = sum - tr;
    }
    output[0] = temporary[0] + temporary[1];
    output[1] = temporary[0] - temporary[1];
    output[n / 2] = temporary[n / 2];
    output[n / 2 + 1] = temporary[n / 2 + 1];
}
static void real_inverse(float *input, float *output, unsigned n) {
    float temporary[128];
    unsigned step = 2048 / n;
    for (unsigned k = 1; k < n / 4; ++k) {
        unsigned a = 2 * k, b = n - 2 * k;
        float diff = (input[b] - input[a]) * -0.5f;
        float sum = (input[b] + input[a]) * 0.5f;
        float imag_sum = (input[b + 1] + input[a + 1]) * -0.5f;
        float imag_diff = (input[a + 1] - input[b + 1]) * 0.5f;
        float cosine = fpc_fft_twiddles[2 * k * step], sine = fpc_fft_twiddles[2 * k * step + 1];
        float tr = diff * cosine - imag_sum * sine;
        float ti = diff * sine + imag_sum * cosine;
        temporary[a] = ti + sum;
        temporary[a + 1] = tr + imag_diff;
        temporary[b + 1] = tr - imag_diff;
        temporary[b] = sum - ti;
    }
    temporary[0] = (input[0] + input[1]) * 0.5f;
    temporary[1] = (input[0] - input[1]) * 0.5f;
    temporary[n / 2] = input[n / 2];
    temporary[n / 2 + 1] = input[n / 2 + 1];
    complex_transform(temporary, output, n / 2, 1);
}
int fpc_profile300_dct(float *values, unsigned n, int inverse) {
    if (!values || n < 8 || n > 128 || (n & (n - 1)))
        return -1;
    unsigned log = 0;
    for (unsigned i = n; i > 1; i /= 2)
        ++log;
    float scale = fpc_dct_scales[log], temporary[128], working[128];
    unsigned step = 1024 / (2 * n);
    if (!inverse) {
        for (unsigned i = 0; i < n / 2; ++i) {
            working[i] = values[2 * i];
            working[n - 1 - i] = values[2 * i + 1];
        }
        real_forward(working, temporary, n);
        values[0] = temporary[0] * 0x1.6a09e6p-1f;
        for (unsigned i = 1; i < n / 2; ++i) {
            unsigned low = 2 * i * step, high = (n + 2 * i) * step;
            values[i] = fpc_fft_twiddles[low] * temporary[2 * i] -
                        fpc_fft_twiddles[low + 1] * temporary[2 * i + 1];
            values[n / 2 + i] = fpc_fft_twiddles[high] * temporary[n - 2 * i] +
                                fpc_fft_twiddles[high + 1] * temporary[n - 2 * i + 1];
        }
        values[n / 2] = fpc_fft_twiddles[n * step] * temporary[1];
    } else {
        working[0] = values[0] * 0x1.6a09e6p+0f;
        for (unsigned i = 1; i < n / 2; ++i) {
            unsigned low = 2 * i * step, high = 2 * (n - i) * step;
            working[2 * i] =
                fpc_fft_twiddles[high] * values[n - i] + fpc_fft_twiddles[low] * values[i];
            working[2 * i + 1] =
                fpc_fft_twiddles[high + 1] * values[n - i] - fpc_fft_twiddles[low + 1] * values[i];
        }
        working[1] = fpc_fft_twiddles[n * step] * values[n / 2];
        real_inverse(working, temporary, n);
        for (unsigned i = 0; i < n / 2; ++i) {
            values[2 * i] = temporary[i];
            values[2 * i + 1] = temporary[n - 1 - i];
        }
    }
    for (unsigned i = 0; i < n; ++i)
        values[i] = values[i] * scale;
    return 0;
}
const int16_t *fpc_profile300_descriptor_weights(void) { return fpc_descriptor_weights; }

static int16_t q6(float value) {
    float scaled = value * 64.0f;
    scaled = scaled <= 0.0f ? scaled - 0.5f : scaled + 0.5f;
    return (int16_t)(int32_t)scaled;
}
static void normalize(int16_t *image, const uint8_t *flags, int percentile) {
    int minimum = INT16_MAX, maximum = INT16_MIN, count = 0;
    for (unsigned i = 0; i < FPC_PIXELS; ++i)
        if (flags[i] & 14) {
            if (image[i] < minimum)
                minimum = image[i];
            if (image[i] > maximum)
                maximum = image[i];
            ++count;
        }
    if (!count || minimum == INT16_MAX || maximum == INT16_MIN)
        return;
    if (percentile) {
        unsigned histogram[512] = {0};
        int scale = maximum == minimum ? 1024 : (511 << 16) / (maximum - minimum);
        for (unsigned i = 0; i < FPC_PIXELS; ++i)
            if (flags[i] & 14) {
                int bin = (scale * (image[i] - minimum) + 32768) >> 16;
                if (bin < 0)
                    bin = 0;
                if (bin > 511)
                    bin = 511;
                ++histogram[bin];
            }
        int lower = (int)((float)count * 0.001f), upper = (int)((1.0f - 0.99f) * (float)count);
        unsigned cumulative = 0;
        int low = 0, high = 511;
        for (; low < 512; ++low) {
            cumulative += histogram[low];
            if (cumulative > (unsigned)lower)
                break;
        }
        cumulative = 0;
        for (; high >= 0; --high) {
            cumulative += histogram[high];
            if (cumulative > (unsigned)upper)
                break;
        }
        if (low == 512 || high < 0)
            return;
        int range = maximum - minimum;
        maximum = minimum + high * range / 511;
        minimum = minimum + low * range / 511;
        if (minimum < 0)
            minimum = 0;
        if (maximum > 16320)
            maximum = 16320;
    }
    if (maximum <= minimum)
        return;
    int scale = 4177920 / (maximum - minimum);
    for (unsigned i = 0; i < FPC_PIXELS; ++i) {
        /* Preserve the original modulo-32 product and arithmetic shift. */
        int32_t value = (int32_t)((uint32_t)(image[i] - minimum) * (uint32_t)scale);
        value >>= 8;
        if (value < 0)
            value = 0;
        if (value > 16320)
            value = 16320;
        image[i] = (int16_t)value;
    }
}
/* 04ae10: first product precedes the old accumulator in each group of four. */
static float projection(const float *pixels, const float *weights, unsigned count) {
    float sum = 0.0f;
    for (unsigned i = 0; i < count; i += 4)
        sum = ((pixels[i] * weights[i] + sum) + pixels[i + 1] * weights[i + 1]) +
              pixels[i + 2] * weights[i + 2] + pixels[i + 3] * weights[i + 3];
    return sum;
}
static int correct_projection(int16_t *image, float *working, float *temporary) {
    float mean = 0.0f, scores[88], smooth[88], strip[112], projected[80];
    for (unsigned i = 0; i < FPC_PIXELS; ++i)
        working[i] = (float)image[i] * 0.015625f;
    for (unsigned y = 0; y < 88; ++y)
        for (unsigned x = 16; x < 96; ++x)
            mean = mean + working[y * 112 + x];
    mean = mean / 7040.0f;
    for (unsigned y = 0; y < 88; ++y) {
        for (unsigned x = 0; x < 80; ++x)
            strip[x] = working[y * 112 + x + 16] - mean;
        for (unsigned x = 0; x < 80; ++x)
            projected[x] = projection(strip, fpc_quality_projection + x * 80, 80);
        float sum = 0.0f;
        for (unsigned x = 0; x < 80; ++x)
            sum = sum + projected[x] * strip[x];
        scores[y] = sum;
    }
    float sum = 0.0f, reciprocal = 1.0f / 15.0f;
    for (unsigned i = 0; i < 15; ++i)
        sum = sum + scores[i];
    for (unsigned i = 0; i < 8; ++i)
        smooth[i] = sum * reciprocal;
    /* 05c780 starts its recurrence at round(15/2), using the preceding output. */
    for (unsigned i = 8; i <= 80; ++i) {
        smooth[i] = (scores[i + 7] - scores[i - 8]) * reciprocal + smooth[i - 1];
    }
    for (unsigned i = 81; i < 88; ++i)
        smooth[i] = smooth[80];
    float maximum = -3.402823466e38f;
    for (unsigned i = 0; i < 88; ++i)
        if (!(smooth[i] <= maximum))
            maximum = smooth[i];
    if (maximum <= 10000.0f)
        return 0;
    mean = 0.0f;
    for (unsigned i = 0; i < FPC_PIXELS; ++i)
        mean = mean + working[i];
    mean = mean / (float)FPC_PIXELS;
    for (unsigned y = 0; y < 88; ++y) {
        float correction[14];
        for (unsigned x = 0; x < 112; ++x)
            strip[x] = working[y * 112 + x] - mean;
        for (unsigned x = 0; x < 14; ++x)
            correction[x] = projection(strip, fpc_correction_projection + x * 112, 112);
        for (unsigned x = 0; x < 112; ++x)
            working[y * 112 + x] = working[y * 112 + x] - correction[x / 8];
    }
    /* 056880: center+left+right, horizontal pass followed by vertical pass. */
    for (unsigned y = 0; y < 88; ++y)
        for (unsigned x = 0; x < 112; ++x) {
            unsigned left = x ? x - 1 : 0, right = x < 111 ? x + 1 : 111;
            temporary[y * 112 + x] =
                (working[y * 112 + x] + working[y * 112 + left]) + working[y * 112 + right];
        }
    for (unsigned y = 0; y < 88; ++y)
        for (unsigned x = 0; x < 112; ++x) {
            unsigned top = y ? y - 1 : 0, bottom = y < 87 ? y + 1 : 87;
            working[y * 112 + x] = ((temporary[y * 112 + x] + temporary[top * 112 + x]) +
                                    temporary[bottom * 112 + x]) *
                                   0.11111111f;
        }
    for (unsigned i = 0; i < FPC_PIXELS; ++i)
        image[i] = q6(working[i]);
    return 100;
}
static unsigned reflect(int position, unsigned size) {
    if (position < 0)
        return (unsigned)(-position - 1);
    if (position >= (int)size)
        return (unsigned)(2 * (int)size - position - 1);
    return (unsigned)position;
}
static void enhance(int16_t *image, float *plane) {
    float line[128];
    /* 0749f0: vertical transform, then horizontal; symmetric edge padding. */
    for (unsigned x = 0; x < 112; ++x) {
        for (unsigned y = 0; y < 128; ++y)
            line[y] = (float)image[reflect((int)y - 20, 88) * 112 + x] * 0.015625f;
        fpc_profile300_dct(line, 128, 0);
        for (unsigned y = 0; y < 128; ++y)
            plane[y * 128 + x + 8] = line[y];
    }
    for (unsigned y = 0; y < 128; ++y) {
        for (unsigned x = 0; x < 8; ++x)
            plane[y * 128 + x] = plane[y * 128 + 15 - x];
        for (unsigned x = 120; x < 128; ++x)
            plane[y * 128 + x] = plane[y * 128 + 239 - x];
        fpc_profile300_dct(plane + y * 128, 128, 0);
    }
    for (unsigned i = 0; i < 128 * 128; ++i)
        plane[i] = plane[i] * fpc_enhancement[i];
    for (unsigned y = 0; y < 128; ++y)
        fpc_profile300_dct(plane + y * 128, 128, 1);
    for (unsigned x = 8; x < 120; ++x) {
        for (unsigned y = 0; y < 128; ++y)
            line[y] = plane[y * 128 + x];
        fpc_profile300_dct(line, 128, 1);
        for (unsigned y = 0; y < 88; ++y)
            image[y * 112 + x - 8] = q6(line[y + 20]);
    }
}
/* 05de20: close five times, fill vertical/horizontal spans, border, erode ten.
 */
static void morph(uint8_t *grid, uint8_t *temporary, int dilate) {
    for (unsigned y = 0; y < 100; ++y)
        for (unsigned x = 0; x < 128; ++x) {
            unsigned i = y * 128 + x;
            uint8_t a = x ? grid[i - 1] : !dilate, b = x < 127 ? grid[i + 1] : !dilate;
            temporary[i] = dilate ? (grid[i] | a | b) : (grid[i] & a & b);
        }
    for (unsigned y = 0; y < 100; ++y)
        for (unsigned x = 0; x < 128; ++x) {
            unsigned i = y * 128 + x;
            uint8_t a = y ? temporary[i - 128] : !dilate, b = y < 99 ? temporary[i + 128] : !dilate;
            grid[i] = dilate ? (temporary[i] | a | b) : (temporary[i] & a & b);
        }
}
static unsigned capture_mask(fpc_prepared_capture *output) {
    uint8_t grid[12800] = {0}, temporary[12800];
    for (unsigned y = 0; y < 88; ++y)
        for (unsigned x = 0; x < 112; ++x)
            grid[(y + 6) * 128 + x + 6] = !!output->mask[y * 112 + x];
    for (unsigned i = 0; i < 5; ++i)
        morph(grid, temporary, 1);
    for (unsigned i = 0; i < 5; ++i)
        morph(grid, temporary, 0);
    for (unsigned x = 0; x < 128; ++x) {
        unsigned first = 100, last = 0;
        for (unsigned y = 0; y < 100; ++y)
            if (grid[y * 128 + x]) {
                if (first == 100)
                    first = y;
                last = y;
            }
        if (first != 100)
            for (unsigned y = first; y <= last; ++y)
                grid[y * 128 + x] = 1;
    }
    for (unsigned y = 0; y < 100; ++y) {
        unsigned first = 128, last = 0;
        for (unsigned x = 0; x < 128; ++x)
            if (grid[y * 128 + x]) {
                if (first == 128)
                    first = x;
                last = x;
            }
        if (first != 128)
            for (unsigned x = first; x <= last; ++x)
                grid[y * 128 + x] = 1;
    }
    for (unsigned y = 0; y < 100; ++y)
        for (unsigned x = 0; x < 128; ++x)
            if (y < 6 || y >= 94 || x < 6 || x >= 118)
                grid[y * 128 + x] = 1;
    for (unsigned i = 0; i < 10; ++i)
        morph(grid, temporary, 0);
    unsigned valid = 0;
    for (unsigned y = 0; y < 88; ++y)
        for (unsigned x = 0; x < 112; ++x) {
            unsigned i = y * 112 + x;
            output->mask[i] = grid[(y + 6) * 128 + x + 6] ? 255 : 0;
            if (output->mask[i]) {
                output->packed_mask[y * 4 + x / 32] |= 1u << (x % 32);
                ++valid;
            }
        }
    return valid;
}
static void box15(uint16_t *image, uint16_t *temporary) {
    for (unsigned y = 0; y < 88; ++y) {
        uint32_t sum = 0;
        for (unsigned x = 0; x < 15; ++x)
            sum += image[y * 112 + x];
        for (unsigned x = 7; x <= 104; ++x) {
            temporary[y * 112 + x] = (uint16_t)((sum * 4369 + 32768) >> 16);
            if (x < 104)
                sum = sum - image[y * 112 + x - 7] + image[y * 112 + x + 8];
        }
        for (unsigned x = 0; x < 7; ++x)
            temporary[y * 112 + x] = temporary[y * 112 + 7];
        for (unsigned x = 105; x < 112; ++x)
            temporary[y * 112 + x] = temporary[y * 112 + 104];
    }
    for (unsigned x = 0; x < 112; ++x) {
        uint32_t sum = 0;
        for (unsigned y = 0; y < 15; ++y)
            sum += temporary[y * 112 + x];
        for (unsigned y = 7; y <= 80; ++y) {
            image[y * 112 + x] = (uint16_t)((sum * 4369 + 32768) >> 16);
            if (y < 80)
                sum = sum - temporary[(y - 7) * 112 + x] + temporary[(y + 8) * 112 + x];
        }
        for (unsigned y = 0; y < 7; ++y)
            image[y * 112 + x] = image[7 * 112 + x];
        for (unsigned y = 81; y < 88; ++y)
            image[y * 112 + x] = image[80 * 112 + x];
    }
}
int fpc_profile300_frame_score(const uint8_t *pixels, size_t size) {
    if (!pixels || size != FPC_PIXELS)
        return -1;
    uint16_t *image = malloc(FPC_PIXELS * sizeof(uint16_t)),
             *temporary = malloc(FPC_PIXELS * sizeof(uint16_t));
    if (!image || !temporary) {
        free(image);
        free(temporary);
        return -1;
    }
    for (unsigned i = 0; i < FPC_PIXELS; ++i)
        image[i] = (uint16_t)(pixels[i] * 16);
    box15(image, temporary);
    for (unsigned i = 0; i < FPC_PIXELS; ++i) {
        int difference = (int)image[i] - (int)pixels[i] * 16;
        image[i] = (uint16_t)(difference < 0 ? -difference : difference);
    }
    box15(image, temporary);
    unsigned contrast = 0;
    for (unsigned i = 0; i < FPC_PIXELS; ++i)
        contrast += image[i] > 208;
    free(image);
    free(temporary);
    int saturation = fpc_saturation_quality(pixels, size);
    return (3072 * saturation + 1024 * (int)(contrast * 1000 / FPC_PIXELS) + 2048) >> 12;
}
int fpc_profile300_rank_frames(const uint8_t *const *frames, size_t count, unsigned order[5]) {
    if (!frames || !order || !count || count > 5)
        return -1;
    int scores[5];
    for (size_t i = 0; i < count; ++i) {
        scores[i] = fpc_profile300_frame_score(frames[i], FPC_PIXELS);
        if (scores[i] < 0)
            return -1;
        order[i] = (unsigned)i;
    }
    for (size_t i = 1; i < count; ++i) {
        size_t j = i;
        unsigned selected = order[i];
        while (j && scores[selected] > scores[order[j - 1]]) {
            order[j] = order[j - 1];
            --j;
        }
        order[j] = selected;
    }
    return 0;
}
int fpc_profile300_prepare(const uint8_t *pixels, size_t size, const uint16_t *dead,
                           size_t dead_count, fpc_prepared_capture *output) {
    if (!pixels || size != FPC_PIXELS || !output || dead_count > 560 || (dead_count && !dead))
        return -1;
    float *working = malloc(FPC_PIXELS * sizeof(float)),
          *temporary = malloc(128 * 128 * sizeof(float));
    int16_t *image = malloc(FPC_PIXELS * sizeof(int16_t));
    uint8_t *flags = malloc(FPC_PIXELS);
    if (!working || !temporary || !image || !flags) {
        free(working);
        free(temporary);
        free(image);
        free(flags);
        return 2;
    }
    int status = fpc_classify_raw_pixels(pixels, 112, 88, 112, dead, dead_count, flags, 112);
    if (status)
        goto done;
    for (unsigned i = 0; i < FPC_PIXELS; ++i)
        working[i] = (float)pixels[i];
    status = fpc_process_raw_pixel_defects(working, flags, 112, 88, dead, dead_count, 0, 560, 1);
    if (status)
        goto done;
    memset(output, 0, sizeof(*output));
    output->quality = 100;
    for (unsigned i = 0; i < FPC_PIXELS; ++i)
        image[i] = q6(working[i]);
    output->filter_reason = correct_projection(image, working, temporary);
    normalize(image, flags, 0);
    enhance(image, temporary);
    normalize(image, flags, 1);
    for (unsigned y = 0; y < 88; ++y)
        for (unsigned x = 0; x < 112; ++x) {
            unsigned i = y * 112 + x;
            output->pixels[i] = (uint8_t)((image[i] + 32) >> 6);
            if (flags[i] & 14) {
                output->mask[i] = 255;
                output->prepared_mask[y * 4 + x / 32] |= 1u << (x % 32);
            }
        }
    unsigned valid = capture_mask(output);
    uint8_t angles[FPC_PIXELS], confidence[FPC_PIXELS];
    status = fpc_hessian_orientation(output->pixels, 112, 88, 112, 1.0f, 0.0f, angles, confidence);
    if (status)
        goto done;
    unsigned sum = 0;
    for (unsigned i = 0; i < FPC_PIXELS; ++i)
        if (output->mask[i])
            sum += confidence[i];
    output->confidence = (int)(sum / (valid + 1));
    output->coverage = (int)(((float)valid * 100.0f) / (float)FPC_PIXELS + 0.5f);
    output->is_finger = output->confidence >= 20 && output->coverage >= 30;
    status = fpc_extract_profile300_prepared(output->pixels, 112, output->mask, 112,
                                             fpc_descriptor_weights, 16384, output->features, 300,
                                             &output->feature_count);
done:
    free(working);
    free(temporary);
    free(image);
    free(flags);
    return status;
}
