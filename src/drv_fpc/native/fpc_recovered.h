#ifndef FPC_RECOVERED_H
#define FPC_RECOVERED_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Recovered arithmetic and wire primitives. The profile300 adapter owns the
 * capture, enrollment, identification and persistence lifecycle. */
uint32_t fpc_crc32(const uint8_t *data, size_t size);
/* Return 0 on valid framing/checksums, -1 on malformed input.
 * This does not validate feature payloads or template compatibility. */
int fpc_template_validate(const uint8_t *data, size_t size,
                          uint32_t *version, size_t *blocks);
/* Return saturation quality 0..1000; -1 for empty/null input. */
int fpc_saturation_quality(const uint8_t *pixels, size_t count);
/* Score remap only: overlap must already come from the geometric matcher.
 * coeff order: bias, raw score, probe feature count, overlap. */
int fpc_score_remap(int raw_score, int probe_features, int overlap,
                    const int16_t coeff[4], int maximum);
/* Binary projection descriptor for modes 0..4, given an already sampled patch.
 * weights are little-endian int16 data decoded by the caller, pixel-major.
 * descriptor_bytes must be positive and even. */
int fpc_project_descriptor(const uint8_t *patch, size_t pixels,
                           const int16_t *weights, size_t weight_count,
                           uint8_t *descriptor, size_t descriptor_bytes);
unsigned fpc_descriptor_distance32(uint32_t first, uint32_t second);
/* Q15 affine mapping [xx, xy, x0, yx, yy, y0]; reject out-of-bounds
 * four-pixel neighborhoods rather than inventing padding behavior. */
int fpc_sample_affine_q15(const uint8_t *source, size_t width, size_t height,
                          size_t stride, uint8_t *patch, size_t patch_width,
                          size_t patch_height, const int32_t affine[6]);
/* Original polynomial approximation; angles in radians. */
int fpc_sincos_recovered(float radians, float *cosine, float *sine);
/* Mode-specific descriptor patch sampling, orientation in degrees. */
int fpc_sample_descriptor_patch(const uint8_t *source, size_t width,
                                size_t height, size_t stride, uint8_t *patch,
                                unsigned side, unsigned source_span,
                                uint8_t x, uint8_t y, float degrees);
typedef struct {
    uint8_t x, y;
    uint16_t reserved;
    float score;
} fpc_keypoint;
/* Detector branch 0. Mask=255 enables response calculation; nonzero enables
 * selection. Border must be >=3. Caller supplies width*height response bytes. */
int fpc_detect_circle9(const uint8_t *image, size_t width, size_t height,
                        size_t stride, const uint8_t *mask, size_t mask_stride,
                        unsigned threshold, unsigned border, uint8_t *responses,
                        fpc_keypoint *points, size_t capacity, size_t *count);
/* Branch 2: inputs are filtered signed-16 Hessian planes, not image pixels. */
int fpc_harris_scores(const int16_t *xx, const int16_t *yy, const int16_t *xy,
                       size_t count, float k, float *scores);
int fpc_select_float_maxima(const float *scores, size_t width, size_t height,
                             size_t stride, const uint8_t *mask, size_t mask_stride,
                             unsigned border, fpc_keypoint *points,
                             size_t capacity, size_t *count);
/* Gaussian, first derivative and second derivative: 15 signed Q15 taps. */
int fpc_gaussian_derivative_kernels(float sigma, int16_t gaussian[15],
                                    int16_t first[15], int16_t second[15]);
/* 18006ad20: Hessian planes from an 8-bit image, input converted to Q6.
 * Output arrays contain width*height signed-16 values. */
int fpc_hessian_planes(const uint8_t *image, size_t width, size_t height,
                        size_t stride, float sigma, int16_t *xx,
                        int16_t *yy, int16_t *xy);
/* Mode-4 angle encoding helpers: signed byte represents half-turn orientation. */
void fpc_angle_vector(uint8_t angle, int32_t *cos_double, int32_t *sin_double);
int32_t fpc_angle_fixed(int32_t first, int32_t second);
int fpc_interpolate_orientation(const uint8_t *field, size_t width, size_t height,
                                 int32_t x_q4, int32_t y_q4, int8_t *angle);
/* Mode-4 coarse field, dimensions (image_width-4)/4 by (image_height-4)/4.
 * Caller supplies that many bytes. Input must be the prepared descriptor image. */
int fpc_build_orientation_field(const uint8_t *image, size_t width, size_t height,
                                 size_t stride, uint8_t *field, size_t field_size);
/* 180045910, table-seeded float approximation; preserves original bit math. */
float fpc_sqrt_recovered(float input);
/* 180046200, coefficient mode 5; signed smoothed double-angle vectors. */
uint8_t fpc_hessian_angle(int16_t sine, int16_t cosine);
/* Full-resolution 180048820 path. Even width and height,
 * dimensions 16..256; derivative sigma 1..10; positive regularizer.
 * Outputs each contain width*height bytes. */
int fpc_hessian_orientation(const uint8_t *image, size_t width, size_t height,
                             size_t stride, float sigma, float regularizer,
                             uint8_t *angles, uint8_t *confidence);
typedef struct {int32_t index; int16_t x,y;} fpc_ranked_location;
/* 18006f000: spatial balancing of already ranked locations, 3x3 grid.
 * Preserves input ranking within each cell; deterministic cell permutation.
 * Returns selected original indices. Bounds are inclusive. */
int fpc_select_spatial_features(const fpc_ranked_location *ranked, size_t count,
                                size_t wanted, int16_t xmin, int16_t ymin,
                                int16_t xmax, int16_t ymax, int32_t *indices);
typedef struct {int32_t index; float score;} fpc_ranked_score;
/* Original descending quicksort, preserving its equal-score permutation. */
int fpc_sort_feature_scores(fpc_ranked_score *records, size_t count);
/* 18004d0d0: separable Q15 downsampling, including per-pass rounding.
 * Each output dimension must be strictly smaller than the source dimension. */
int fpc_resize_down(const uint8_t *source, size_t width, size_t height,
                    size_t stride, uint8_t *output, size_t output_width,
                    size_t output_height, size_t output_stride);
/* 18006a3c0: seven-tap Q6 Gaussian image smoothing before downsampling. */
int fpc_blur_image7(const uint8_t *source, size_t width, size_t height,
                    size_t stride, float sigma, uint8_t *output,
                    size_t output_stride);
/* 180051b40: expand little-endian word mask into 0/255 byte ROI.
 * Packed rows must be aligned to 32 bits. */
int fpc_expand_mask(const uint32_t *words, size_t word_count, size_t bit_stride,
                     size_t origin_x, size_t origin_y, size_t width, size_t height,
                     uint8_t *output, size_t output_stride);
/* 18004d3e0 with thresholds 254/0: keep only exactly-255 mask pixels. */
int fpc_threshold_resized_mask(uint8_t *mask, size_t width, size_t height,
                                size_t stride);
/* 055550 initial raw-pixel classification:0=>1,255=>16,other=>2;
 * listed defective linear indices override to4. These flags precede quality-mask
 * processing and are not the extractor's final binary mask. */
int fpc_classify_raw_pixels(const uint8_t *image, size_t width, size_t height,
                             size_t image_stride, const uint16_t *defective_indices,
                             size_t defective_count, uint8_t *flags, size_t flags_stride);
/* 07a240 normal defective-pixel interpolation (mode4 extra correction excluded).
 * Contiguous float image. Returns1001 if required count/completion gate fails,
 * 2 allocation failure,-1 invalid input. Unresolved pixels otherwise preserved. */
int fpc_correct_defective_pixels(float *image, size_t width, size_t height,
                                  const uint16_t *indices, size_t count,
                                  uint16_t maximum_count, int require_all);
/* 07a6b0: source flag bits1/16 select saturated pixels; working bit2 selects
 * eligible neighbors. Filled pixels become flag8 and are excluded thereafter. */
int fpc_fill_saturated_pixels(float *image, size_t width, size_t height,
                               const uint8_t *source_flags, uint8_t *working_flags);
/* 079840 modes0..4 saturation/defect dispatch, preserving original flag writes.
 * Mode4 propagates prior-pass corrections through5x5 windows. Failure can leave
 * image modified. Modes0/4 do not require or change flags. */
int fpc_process_raw_pixel_defects(float *image, uint8_t *flags, size_t width, size_t height,
                                   const uint16_t *indices, size_t count, unsigned mode,
                                   uint16_t maximum_count, int require_all);
/* 18004cbd0 symmetric padding: replicate edge pixels including corners.
 * Source/destination must not overlap. Output extents add 2*padding. */
int fpc_pad_image_edges(const uint8_t *source, size_t width, size_t height,
                         size_t stride, size_t padding, uint8_t *output,
                         size_t output_stride);
typedef struct {
    size_t count;
    int16_t scale_x_q14,scale_y_q14,offset_x_q4,offset_y_q4;
} fpc_feature_level;
/* 18005e170: one/two-level quota, ranking and spatial budget selection.
 * Input points are consecutive levels. Output remains in level order.
 * Input/output arrays must not overlap; capacity must cover input count.
 * Negative budget or count <= budget preserves all points. */
int fpc_limit_feature_budget(const fpc_keypoint *points, size_t count,
                              const fpc_feature_level *levels, size_t level_count,
                              size_t image_width, size_t image_height, int budget,
                              fpc_keypoint *output, size_t capacity,
                              size_t *output_count, size_t selected_per_level[2]);
typedef struct {fpc_keypoint point; float degrees; uint8_t descriptor[16];} fpc_feature;
/* Profile 300 extractor from an already preprocessed 112x88 image and byte mask.
 * Does not perform sensor calibration or raw-image preprocessing.
 * Caller supplies recovered mode-4 coefficients (16384 signed words).
 * Output capacity must be at least 300 features. */
int fpc_extract_profile300_prepared(const uint8_t *image, size_t stride,
                                    const uint8_t *mask, size_t mask_stride,
                                    const int16_t *weights, size_t weight_count,
                                    fpc_feature *output, size_t capacity,
                                    size_t *count);
/* 180071820: minimum full-descriptor Hamming distance over half-swap rotation. */
unsigned fpc_descriptor_distance128(const uint8_t first[16], const uint8_t second[16]);
typedef struct {uint16_t first,second,distance; uint8_t flag,reserved;} fpc_candidate;
/* 1800528b0: replace malloc-owned array, preserving full entry bytes/order.
 * Filtered mode requires final_inliers to equal nonzero flag count.
 * Returns2 for allocation failure, -1 for invalid input, 0 on success. */
int fpc_compact_candidates(fpc_candidate **owned_pairs, size_t *count,
                            size_t final_inliers, int filter);
/* Pair payload0529b0, flags1000 required;2000 filters,4000 distance,8000 flag.
 * Size query with output=NULL; invalid filtered count rejected before writes. */
int fpc_pair_payload(const fpc_candidate *pairs, size_t count, uint32_t inliers,
                       uint8_t success, const int16_t transform[4], uint16_t flags,
                       uint8_t *output, size_t capacity, size_t *written);
typedef struct {
    fpc_candidate *pairs;
    size_t count;
    uint32_t inliers;
    uint8_t success;
    int16_t transform[4];
} fpc_loaded_pair;
int fpc_pair_load_payload(const uint8_t *data, size_t size, uint16_t flags,
                            fpc_loaded_pair *output);
void fpc_loaded_pair_destroy(fpc_loaded_pair *pair);
typedef struct {
    uint32_t count;
    uint8_t mode,descriptor_bytes,levels,table_width;
    const uint16_t *level_fields; /* five words per level in serialized order */
    const uint16_t *level_extra; /* table_width-1 words per level */
    const uint8_t *compact_coordinates,*descriptors,*membership;
    const uint32_t *coordinates,*scores,*angles; /* raw float/integer bits */
} fpc_capture_payload_view;
int fpc_capture_payload(const fpc_capture_payload_view *view, uint16_t flags,
                          uint8_t *output, size_t capacity, size_t *written);
typedef struct {fpc_capture_payload_view view; void *storage;} fpc_loaded_capture;
/* Current-format owned view; full payload requires level counts sum to count. */
int fpc_capture_load_payload(const uint8_t *data, size_t size, uint16_t flags,
                               fpc_loaded_capture *output);
void fpc_loaded_capture_destroy(fpc_loaded_capture *capture);
int fpc_collection_serialize_default(const fpc_capture_payload_view *captures,
                                       size_t count, uint32_t capture_capacity,
                                       uint8_t *output, size_t capacity, size_t *written);
typedef struct {
    fpc_loaded_capture *captures;
    size_t count;
    uint32_t capacity;
} fpc_loaded_collection;
int fpc_collection_load_default(const uint8_t *data, size_t size,
                                  fpc_loaded_collection *output, size_t *consumed);
void fpc_loaded_collection_destroy(fpc_loaded_collection *collection);
/* 0417e0 append/replace ownership transfer; incoming zeroed only on success.
 * Index may equal count if spare capacity exists. Returns1 invalid,2 allocation. */
int fpc_loaded_collection_take_capture(fpc_loaded_collection *collection,
                                        fpc_loaded_capture *incoming, size_t index);
/* 054230: group state payload; nine matrix words preserve raw float bits. */
int fpc_group_payload(size_t count, int16_t group_count, const int16_t *groups,
                       const uint16_t *roots, const uint32_t *matrix_bits,
                       uint8_t *output, size_t capacity, size_t *written);
typedef struct {
    size_t count;
    int16_t group_count;
    int16_t *groups;
    uint16_t *roots;
    uint32_t *matrix_bits;
    void *storage;
} fpc_loaded_groups;
int fpc_group_load_payload(const uint8_t *data, size_t size, fpc_loaded_groups *output);
void fpc_loaded_groups_destroy(fpc_loaded_groups *groups);
/* 180052f60: mutual nearest neighbors, first-index tie breaking, strict threshold.
 * Matrix rows may have padding. Capacity must cover first_count. */
int fpc_mutual_candidates(const uint8_t *matrix, size_t first_count,
                           size_t second_count, size_t stride, unsigned threshold,
                           uint16_t first_offset, uint16_t second_offset,
                           fpc_candidate *output, size_t capacity, size_t *count);
/* Geometry uses source/target coordinate pairs in signed Q4 units. */
typedef struct {int16_t x,y,target_x,target_y;} fpc_match_coordinates;
/* Two-correspondence similarity: Q14 cosine/scale,sine/scale; Q4 translations.
 * Degenerate source pairs return -1 rather than original division fault. */
int fpc_fit_similarity_pair(const fpc_match_coordinates *a,
                            const fpc_match_coordinates *b, int16_t transform[4]);
int fpc_sample_geometry_pairs(const fpc_match_coordinates *points, size_t count,
                               uint32_t state[2], unsigned tolerance_shift,
                               int32_t indices[32], uint32_t valid[16]);
uint32_t fpc_similarity_error(const fpc_match_coordinates *point, const int16_t transform[4]);
typedef struct {
    int16_t transform[4];
    int32_t inliers,spatial_inliers;
    uint8_t success,low_movement;
} fpc_geometry_result;
/* Complete profile-300 verification on already converted signed Q4 pairs.
 * Membership bitmaps indexed by candidate feature indices, updated as original.
 * Does not convert feature blobs or calculate the later template match score. */
int fpc_verify_geometry_profile300(const fpc_match_coordinates *points, size_t count,
                                   fpc_candidate *pairs, const uint8_t *source_membership,
                                   size_t source_membership_size, uint8_t *target_membership,
                                   size_t target_membership_size, fpc_geometry_result *result);
/* 180070250 packed-coordinate path, including signed per-level Q14/Q4 fields.
 * Views may come directly from loaded templates. Raw float coordinates require
 * a separate adapter. Rejects invalid level coverage and candidate indices. */
int fpc_capture_candidate_coordinates(const fpc_capture_payload_view *first,
                                       const fpc_capture_payload_view *second,
                                       const fpc_candidate *pairs, size_t count,
                                       fpc_match_coordinates *output);
/* Loaded single-level packed captures,mode1/16-byte descriptors, profile300 settings.
 * Uses first->membership; target bitmap is caller-owned mutable state.
 * Does not perform template traversal or final identification aggregation. */
int fpc_match_profile300_captures(const fpc_capture_payload_view *first,
                                  const fpc_capture_payload_view *second,
                                  uint8_t *target_membership, size_t target_membership_size,
                                  fpc_candidate *pairs, size_t capacity, size_t *pair_count,
                                  fpc_geometry_result *result);
typedef struct {
    size_t count;
    uint16_t scores[80],spatial_scores[80];
    int16_t transforms[80][4];
    uint16_t score;
    int selected_capture; /* -1 when all scores are zero */
    float rank;
} fpc_collection_match_result;
int fpc_match_profile300_collection(const fpc_loaded_collection *collection,
                                    const fpc_capture_payload_view *query,
                                    uint8_t *query_membership, size_t membership_size,
                                    fpc_collection_match_result *output);
typedef struct {
    int threshold,reported_score_limit,good_score_threshold,good_query_quality_threshold;
} fpc_identification_policy;
typedef struct {
    uint16_t score,reported_score;
    int matched,selected_template,selected_capture,good_quality;
    size_t evaluated;
    uint8_t tested[100];
} fpc_identification_result;
/* Profile300 scoring mode0, optional gates282/283 and pending updates disabled.
 * Shared mutable query membership persists through evaluated templates. */
int fpc_identify_profile300(const fpc_loaded_collection *const *collections, size_t count,
                            const fpc_capture_payload_view *query, int query_quality,
                            uint8_t *query_membership, size_t membership_size,
                            const fpc_identification_policy *policy,
                            fpc_identification_result *output);
/* Single-level profile-300 matching of prepared features with byte coordinates.
 * Geometry result.inliers is the direct profile-300 match score. Membership is
 * caller-owned template state. Candidate capacity must cover first_count.
 * This does not construct enrollment templates or initialize membership state. */
int fpc_match_profile300_features(const fpc_feature *first, size_t first_count,
                                  const fpc_feature *second, size_t second_count,
                                  const uint8_t *source_membership, size_t source_membership_size,
                                  uint8_t *target_membership, size_t target_membership_size,
                                  fpc_candidate *pairs, size_t capacity, size_t *pair_count,
                                  fpc_geometry_result *result);
/* Enrollment's packed symmetric graph has capacity*(capacity-1)/2 uint16
 * scores, no diagonal. Capture swaps preserve the edge between swapped nodes. */
int fpc_enrollment_pair_index(size_t capacity, size_t first, size_t second, size_t *index);
int fpc_enrollment_swap_capture_scores(uint16_t *scores, size_t score_count,
                                      size_t capacity, size_t first, size_t second);
/* 18003d760/18003f110: append or choose replacement by squared spatial-score
 * sums, ordered protection and capture age. -1 means reject new capture.
 * Full-set ordering and age arrays each contain capacity entries. */
int fpc_enrollment_select_capture(const uint16_t *graph, size_t graph_size,
                                  size_t count, size_t capacity,
                                  const uint16_t *new_spatial_scores,
                                  const uint16_t *order, const uint16_t *ages,
                                  size_t protected_count, uint16_t age_threshold,
                                  int32_t *selected);
int fpc_enrollment_write_capture_scores(uint16_t *graph, size_t graph_size,
                                        size_t *count, size_t capacity, size_t capture,
                                        const uint16_t *new_spatial_scores, size_t score_count);
typedef struct {int32_t percent,remaining; uint8_t complete;} fpc_enrollment_progress;
typedef struct {
    uint16_t *scores,*order,*ages;
    size_t score_count;
    size_t age_count;
    uint16_t used,capacity,protected_count,protected_limit,age_threshold;
} fpc_retained_graph;
/* 03e170/03e1c0: saturate used ages, reset index<=used (original boundary).
 * Owned age_count must cover every access; reset returns1 for invalid index. */
int fpc_retained_graph_increment_ages(fpc_retained_graph *graph);
int fpc_retained_graph_reset_age(fpc_retained_graph *graph, int index);
/* Pair spatial scores in append order later*(later-1)/2+earlier.
 * Initializes ownership and identity order; sort with initial_order afterwards.
 * Output must be empty. Returns2 on allocation failure, -1 invalid input. */
int fpc_retained_graph_create(const uint16_t *pair_scores, size_t pair_count,
                               size_t used, uint8_t retention_capacity,
                               uint16_t protection, fpc_retained_graph *output);
void fpc_retained_graph_destroy(fpc_retained_graph *graph);
/* Raw payload of template tag0x12340300, without block framing/CRC.
 * pending_count is graph field40 (pending records themselves are separate). */
int fpc_retained_graph_payload(const fpc_retained_graph *graph, uint16_t pending_count,
                                uint8_t *output, size_t capacity, size_t *written);
/* Current-format graph payload loader. Age block loaded separately.
 * Output must be empty; returns1 for zero used as original, -1 malformed. */
int fpc_retained_graph_load_payload(const uint8_t *data, size_t size,
                                     fpc_retained_graph *output, uint16_t *pending_count);
int fpc_retained_graph_load_ages(fpc_retained_graph *graph, const uint8_t *data,
                                  size_t size, uint8_t retention_capacity);
int fpc_template_serialize_default(const fpc_retained_graph *graph,
                                     const fpc_capture_payload_view *captures, size_t count,
                                     uint32_t capture_capacity, uint16_t metadata,
                                     uint8_t retention_capacity, uint8_t *output,
                                     size_t capacity, size_t *written);
typedef struct {
    fpc_retained_graph graph;
    fpc_loaded_collection collection;
    uint16_t metadata;
} fpc_loaded_template;
int fpc_template_load_default(const uint8_t *data, size_t size,
                                uint8_t retention_capacity, fpc_loaded_template *output);
void fpc_loaded_template_destroy(fpc_loaded_template *template_data);
/* 0343c0: select slot, update retained graph and move owned incoming capture.
 * No selection leaves incoming owned by caller; ages reset by outer update.
 * Matching spatial_scores must cover the template's used capture prefix. */
int fpc_loaded_template_retain_capture(fpc_loaded_template *template_data,
                                       const uint16_t *spatial_scores, size_t score_count,
                                       uint16_t protection, fpc_loaded_capture *incoming,
                                       int32_t *selected);
typedef struct {
    uint16_t minimum_score,protection;
    int16_t minimum_quality28,minimum_quality32;
    int32_t minimum_quality16;
} fpc_template_update_policy;
typedef struct {
    int code,matched,update_allowed,age_update_allowed;
    uint16_t reported_score;
    int8_t selected_capture;
    uint8_t changed;
    int32_t retained_slot;
} fpc_template_update_state;
/* 0341f0 normal path; optional spatial gate283 and invalid-state cleanup304 disabled.
 * State102 becomes103; wrong state returns1041. changed includes age-only updates. */
int fpc_update_template_after_match(fpc_loaded_template *template_data,
                                    fpc_loaded_capture *incoming,
                                    int32_t quality28, int32_t quality32, int32_t quality16,
                                    const uint16_t *spatial_scores, size_t score_count,
                                    const fpc_template_update_policy *policy,
                                    fpc_template_update_state *state, uint8_t *reported_changed);
/* 18003da20: identity over capacity; stable ascending modulo32 squared
 * pair costs over used captures. All16 score bits participate. */
int fpc_enrollment_initial_order(const uint16_t *scores, size_t score_count,
                                  size_t used, size_t capacity,
                                  uint16_t *order, size_t order_count);
typedef struct {
    uint16_t attempts;
    uint8_t rejection_streak,early_complete_latched;
    fpc_enrollment_progress progress;
} fpc_enrollment_quality_state;
/* Profile300 capture fields28,32,16; result bits0,4,15. Returns112 at
 * ten consecutive rejections, 0 otherwise; -1 for invalid inputs.
 * Acceptance preserves progress; rejection recomputes it from prior metrics. */
int fpc_enrollment_quality_profile300(int32_t quality28, int32_t quality32,
                                      int32_t quality16, int32_t accepted_count,
                                      float area, float normalized_motion,
                                      float relative_area_change,
                                      fpc_enrollment_quality_state *state,
                                      uint64_t *rejection_flags);
/* 18003d2c0 / 18003cf70, profile300 mode1 index1: 7 minimum, 13 target.
 * Caller supplies recovered geometry metrics and persistent early-completion latch. */
int fpc_enrollment_progress_profile300(int32_t count, float area,
                                       float normalized_motion, float relative_area_change,
                                       uint8_t *early_complete_latched,
                                       fpc_enrollment_progress *result);
/* Packed coverage masks: uint32 little-endian bit order, word-aligned rows.
 * APIs operate on origin-zero views. Warp uses Q20 nearest-neighbor rounding.
 * Source and destination must not overlap for union/warp. */
int fpc_count_packed_mask(const uint32_t *words, size_t width, size_t height,
                           size_t stride_bits, uint32_t *count);
int fpc_union_packed_mask(uint32_t *destination, size_t width, size_t height,
                           size_t stride_bits, const uint32_t *source,
                           size_t source_width, size_t source_height, size_t source_stride_bits,
                           size_t offset_x, size_t offset_y);
int fpc_warp_packed_mask(const uint32_t *source, size_t source_width, size_t source_height,
                          size_t source_stride_bits, uint32_t *destination,
                          size_t width, size_t height, size_t stride_bits,
                          const float affine[6], uint8_t outside);
/* Row-major 3x3 transform operations with original single-precision ordering.
 * Output may alias inputs. Singular inverse returns -1. */
int fpc_inverse_transform3(const float a[9], float out[9]);
int fpc_compose_transform3(const float a[9], const float b[9], float out[9]);
int fpc_inverse_affine6(const float a[6], float out[6]);
/* 18004bf80: clipped inverse-warp corner bounds and origin-adjusted sampler.
 * Bounds are x,y,width,height. Preserves original truncation and extra pixel. */
int fpc_clip_affine_warp_bounds(const float affine[6], int32_t source_width,
                                int32_t source_height, int32_t canvas_width,
                                int32_t canvas_height, int32_t bounds[4], float local[6]);
/* Original approximate polar conversion used for weighted transform averaging.
 * Parameters are translation x/y, radians, scale. */
float fpc_atan2_approx_float(float sine, float cosine);
int fpc_transform_to_parameters(const float matrix[9], float parameters[4]);
int fpc_parameters_to_transform(const float parameters[4], float matrix[9]);
void fpc_q14_similarity_to_transform(const int16_t fixed[4], float matrix[9]);
typedef struct {int16_t transform[4]; int32_t inliers; uint8_t success;} fpc_capture_match;
/* Pair records are in append order later*(later-1)/2+earlier.
 * Group -1 means unassigned; transforms contains count consecutive 3x3 matrices.
 * Reproduces original traversal, branch overwrite and scalar angle averaging. */
int fpc_weighted_group_transform(const fpc_capture_match *matches, size_t match_count,
                                  size_t count, size_t capture, const int16_t *groups,
                                  const float *transforms, float output[9]);
/* 18003fd10: inverse-transform corners in original order, truncating running
 * extrema after each update. Negative group includes all assigned captures.
 * Empty selection and invalid projective coordinates return -1. */
int fpc_capture_group_bounds(const int32_t *widths, const int32_t *heights,
                              const int16_t *groups, const float *transforms,
                              size_t count, int32_t group, int32_t bounds[4]);
typedef struct {
    int32_t group_count,selected_group,reference_capture;
    float center_x,center_y;
} fpc_capture_groups_state;
/* Complete 18003fef0 grouping and selection. Caller arrays each cover count;
 * transforms contains count*9 floats. Roots and unassigned transforms retain
 * untouched slots. State is persistent between calls; flags is OR-updated. */
int fpc_rebuild_capture_groups(const fpc_capture_match *matches, size_t match_count,
                               size_t count, const int32_t *widths, const int32_t *heights,
                               int32_t minimum_group_size, int preserve_transforms,
                               int16_t *groups, uint16_t *roots, float *transforms,
                               fpc_capture_groups_state *state, uint32_t *flags);
typedef struct {
    int32_t image_width,image_height,mask_width,mask_height;
    size_t mask_stride_bits;
    const uint32_t *mask;
} fpc_capture_coverage;
int fpc_capture_canvas_transform(const float *transforms, size_t count, size_t capture,
                                  uint16_t reference, int32_t reference_width,
                                  int32_t reference_height, int32_t canvas_width,
                                  int32_t canvas_height, float output[9]);
/* 041860 two-pass serialization mutation; unassigned group -1 unchanged. */
int fpc_normalize_group_canvas(const int32_t *widths, const int32_t *heights,
                                const int16_t *groups, const uint16_t *roots,
                                size_t count, int32_t canvas_width,
                                int32_t canvas_height, float *transforms);
/* Complete 180040800 coverage union for origin-zero packed capture masks.
 * Output rows use ceil(canvas_width/32) words. Clears output before union. */
int fpc_build_group_mask_union(const fpc_capture_coverage *captures, size_t count,
                                const int16_t *groups, const uint16_t *roots,
                                const float *transforms, int16_t group,
                                int32_t canvas_width, int32_t canvas_height,
                                uint32_t *output, size_t output_words);
typedef struct {
    float area[80],motion[80];
    float latest_motion,normalized_motion,relative_area_change;
} fpc_enrollment_metrics;
/* 18003c7d0 history calculations after coverage area has been computed.
 * Preserves earlier history and one-capture motion fields. */
int fpc_update_enrollment_metrics(size_t count, float area, int32_t image_width,
                                   int32_t image_height, const fpc_capture_match *matches,
                                   size_t match_count, fpc_enrollment_metrics *state);
/* Complete 18003c7d0 producer for origin-zero packed masks and supplied group
 * state. coverage_percent is capture field64, not arbitrary quality scores. */
int fpc_compute_enrollment_metrics(const fpc_capture_coverage *captures, size_t count,
                                    const int32_t *coverage_percent, const int16_t *groups,
                                    const uint16_t *roots, const float *transforms,
                                    size_t group_count, int32_t canvas_width, int32_t canvas_height,
                                    const fpc_capture_match *matches, size_t match_count,
                                    fpc_enrollment_metrics *state);
/* 18003d240: count<2 preserves both outputs; otherwise equality counts as
 * insufficient movement. Counter increments modulo 2^32. */
int fpc_enrollment_check_movement(size_t count, float area, float latest_motion,
                                  float threshold, uint32_t *insufficient_count,
                                  int32_t *report_flag);
#ifdef __cplusplus
}
#endif
#endif
