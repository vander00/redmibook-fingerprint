#ifndef FPC_NATIVE_ENROLLMENT_H
#define FPC_NATIVE_ENROLLMENT_H
#include "profile300.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct fpc_native_enrollment fpc_native_enrollment;
typedef struct {
    uint64_t rejection_flags;
    fpc_enrollment_progress progress;
    int32_t movement;
    uint32_t group_change;
    size_t accepted;
    float area, latest_motion, normalized_motion, relative_area_change;
} fpc_native_enrollment_report;
int fpc_capture_from_prepared(const fpc_prepared_capture *prepared, int enrolled,
                              fpc_loaded_capture *output);
fpc_native_enrollment *fpc_native_enrollment_create(void);
void fpc_native_enrollment_destroy(fpc_native_enrollment *session);
int fpc_native_enrollment_add(fpc_native_enrollment *session, const fpc_prepared_capture *prepared,
                              fpc_native_enrollment_report *report);
/* Requires completed enrollment; caller owns returned template. */
int fpc_native_enrollment_finish(const fpc_native_enrollment *session, fpc_loaded_template *output);
#ifdef __cplusplus
}
#endif
#endif
