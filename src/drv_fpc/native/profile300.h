#ifndef FPC_PROFILE300_H
#define FPC_PROFILE300_H
#include "fpc_recovered.h"
#ifdef __cplusplus
extern "C" {
#endif
enum { FPC_WIDTH = 112, FPC_HEIGHT = 88, FPC_PIXELS = 9856, FPC_MASK_WORDS = 352 };
typedef struct {
    uint8_t pixels[FPC_PIXELS], mask[FPC_PIXELS];
    uint32_t packed_mask[FPC_MASK_WORDS], prepared_mask[FPC_MASK_WORDS];
    int filter_reason, quality, confidence, coverage, is_finger;
    fpc_feature features[300];
    size_t feature_count;
} fpc_prepared_capture;
int fpc_profile300_frame_score(const uint8_t *pixels, size_t size);
int fpc_profile300_rank_frames(const uint8_t *const *frames, size_t count, unsigned order[5]);
/* Power-of-two transforms, 8..128; input is modified in place. */
int fpc_profile300_dct(float *values, unsigned length, int inverse);
int fpc_profile300_prepare(const uint8_t *pixels, size_t size, const uint16_t *dead,
                           size_t dead_count, fpc_prepared_capture *output);
const int16_t *fpc_profile300_descriptor_weights(void);
#ifdef __cplusplus
}
#endif
#endif
