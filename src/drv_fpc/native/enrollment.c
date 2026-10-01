#include "enrollment.h"
#include <stdlib.h>
#include <string.h>

struct fpc_native_enrollment {
    size_t count, pair_count;
    fpc_loaded_capture captures[13];
    uint32_t masks[13][FPC_MASK_WORDS];
    int32_t coverage[13], widths[13], heights[13];
    fpc_capture_match matches[78];
    uint16_t spatial_scores[78], roots[13];
    int16_t groups[13];
    float transforms[13 * 9];
    fpc_capture_groups_state grouping;
    fpc_enrollment_metrics metrics;
    fpc_enrollment_quality_state quality;
    uint32_t insufficient_movement;
    int failed;
};
int fpc_capture_from_prepared(const fpc_prepared_capture *prepared, int enrolled,
                              fpc_loaded_capture *output) {
    if (!prepared || !output || output->storage || prepared->feature_count > 300)
        return -1;
    size_t n = prepared->feature_count;
    uint16_t fields[5] = {(uint16_t)n, 16384, 16384, 8, 8};
    uint8_t coordinates[600], descriptors[4800], membership[38] = {0}, payload[5500];
    for (size_t i = 0; i < n; ++i) {
        coordinates[2 * i] = prepared->features[i].point.x;
        coordinates[2 * i + 1] = prepared->features[i].point.y;
        memcpy(descriptors + 16 * i, prepared->features[i].descriptor, 16);
        if (enrolled)
            membership[i / 8] |= (uint8_t)(1u << (i % 8));
    }
    fpc_capture_payload_view view = {0};
    view.count = (uint32_t)n;
    view.mode = 1;
    view.descriptor_bytes = 16;
    view.levels = 1;
    view.table_width = 0;
    view.level_fields = fields;
    view.compact_coordinates = coordinates;
    view.descriptors = descriptors;
    view.membership = membership;
    size_t bytes = 0;
    int status = fpc_capture_payload(&view, 0xce1, payload, sizeof(payload), &bytes);
    return status ? status : fpc_capture_load_payload(payload, bytes, 0xce1, output);
}
fpc_native_enrollment *fpc_native_enrollment_create(void) {
    fpc_native_enrollment *session = calloc(1, sizeof(*session));
    if (!session)
        return NULL;
    session->grouping.selected_group = -1;
    session->grouping.reference_capture = -1;
    session->quality.progress.remaining = 13;
    for (unsigned i = 0; i < 13; ++i) {
        session->groups[i] = -1;
        session->widths[i] = 112;
        session->heights[i] = 88;
    }
    return session;
}
void fpc_native_enrollment_destroy(fpc_native_enrollment *session) {
    if (!session)
        return;
    for (size_t i = 0; i < 13; ++i)
        fpc_loaded_capture_destroy(session->captures + i);
    free(session);
}
int fpc_native_enrollment_add(fpc_native_enrollment *s, const fpc_prepared_capture *p,
                              fpc_native_enrollment_report *report) {
    if (!s || !p || !report || s->failed)
        return -1;
    memset(report, 0, sizeof(*report));
    if (s->count >= 13)
        return 111;
    float area = s->count ? s->metrics.area[s->count - 1] : 0.0f;
    int status = fpc_enrollment_quality_profile300(
        p->confidence, p->coverage, p->quality, (int32_t)s->count, area,
        s->metrics.normalized_motion, s->metrics.relative_area_change, &s->quality,
        &report->rejection_flags);
    if (status || report->rejection_flags)
        goto result;
    status = fpc_capture_from_prepared(p, 1, s->captures + s->count);
    if (status)
        goto fail;
    fpc_capture_payload_view *incoming = &s->captures[s->count].view;
    for (size_t i = 0; i < s->count; ++i) {
        fpc_candidate candidates[300];
        size_t candidate_count = 0;
        fpc_geometry_result geometry = {0};
        status = fpc_match_profile300_captures(
            &s->captures[i].view, incoming, (uint8_t *)incoming->membership,
            (incoming->count + 7) / 8, candidates, 300, &candidate_count, &geometry);
        if (status)
            goto fail;
        fpc_capture_match *match = s->matches + s->pair_count;
        memcpy(match->transform, geometry.transform, sizeof(match->transform));
        match->success = geometry.success;
        match->inliers = geometry.success ? geometry.inliers : 0;
        s->spatial_scores[s->pair_count] = (uint16_t)geometry.spatial_inliers;
        ++s->pair_count;
    }
    memcpy(s->masks[s->count], p->packed_mask, sizeof(p->packed_mask));
    s->coverage[s->count] = p->coverage;
    int old_group_count = s->grouping.group_count;
    size_t unassigned_before = 0;
    for (size_t i = 0; i < s->count; ++i)
        unassigned_before += s->groups[i] < 0;
    ++s->count;
    status = fpc_rebuild_capture_groups(s->matches, s->pair_count, s->count, s->widths, s->heights,
                                        4, 0, s->groups, s->roots, s->transforms, &s->grouping,
                                        &report->group_change);
    if (status)
        goto fail;
    report->group_change &= 1;
    size_t unassigned_after = 0;
    for (size_t i = 0; i < s->count; ++i)
        unassigned_after += s->groups[i] < 0;
    if (s->grouping.group_count == old_group_count && unassigned_after <= unassigned_before &&
        s->grouping.selected_group >= 0 && s->groups[s->count - 1] == s->grouping.selected_group)
        report->group_change |= 1;
    fpc_capture_coverage masks[13];
    for (size_t i = 0; i < s->count; ++i) {
        masks[i] = (fpc_capture_coverage){112, 88, 112, 88, 128, s->masks[i]};
    }
    status = fpc_compute_enrollment_metrics(masks, s->count, s->coverage, s->groups, s->roots,
                                            s->transforms, (size_t)s->grouping.group_count, 500,
                                            500, s->matches, s->pair_count, &s->metrics);
    if (status)
        goto fail;
    status = fpc_enrollment_check_movement(s->count, s->metrics.area[s->count - 1],
                                           s->metrics.latest_motion, 0.4f,
                                           &s->insufficient_movement, &report->movement);
    if (status)
        goto fail;
    status = fpc_enrollment_progress_profile300(
        (int32_t)s->count, s->metrics.area[s->count - 1], s->metrics.normalized_motion,
        s->metrics.relative_area_change, &s->quality.early_complete_latched, &s->quality.progress);
    if (status)
        goto fail;
result:
    report->area = s->count ? s->metrics.area[s->count - 1] : 0.0f;
    report->latest_motion = s->metrics.latest_motion;
    report->normalized_motion = s->metrics.normalized_motion;
    report->relative_area_change = s->metrics.relative_area_change;
    report->accepted = s->count;
    report->progress = s->quality.progress;
    return status;
fail:
    s->failed = 1;
    return status;
}
int fpc_native_enrollment_finish(const fpc_native_enrollment *s, fpc_loaded_template *output) {
    if (!s || !output || s->failed || !s->quality.progress.complete || output->collection.captures)
        return -1;
    fpc_retained_graph graph = {0};
    int status =
        fpc_retained_graph_create(s->spatial_scores, s->pair_count, s->count, 32, 8, &graph);
    if (status)
        return status;
    status = fpc_enrollment_initial_order(graph.scores, graph.score_count, graph.used,
                                          graph.capacity, graph.order, graph.capacity);
    fpc_capture_payload_view views[13];
    for (size_t i = 0; i < s->count; ++i)
        views[i] = s->captures[i].view;
    size_t bytes = 0;
    if (!status)
        status =
            fpc_template_serialize_default(&graph, views, s->count, 32, 0, 32, NULL, 0, &bytes);
    uint8_t *payload = status ? NULL : malloc(bytes);
    if (!status && !payload)
        status = 2;
    if (!status)
        status = fpc_template_serialize_default(&graph, views, s->count, 32, 0, 32, payload, bytes,
                                                &bytes);
    if (!status)
        status = fpc_template_load_default(payload, bytes, 32, output);
    free(payload);
    fpc_retained_graph_destroy(&graph);
    return status;
}
