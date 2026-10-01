#include "fpc_recovered.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void store_le32(uint8_t *p,uint32_t value) {
    for (unsigned i=0;i<4;++i) p[i]=(uint8_t)(value>>(8*i));
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 |
           (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

/* 1800426a0 / 180042870; table at 1800871f0. */
uint32_t fpc_crc32(const uint8_t *data, size_t size) {
    uint32_t crc = UINT32_MAX;
    for (size_t i=0; i<size; ++i) {
        crc ^= data[i];
        for (unsigned j=0; j<8; ++j)
            crc = (crc>>1) ^ (UINT32_C(0xedb88320) & (0u-(crc&1u)));
    }
    return ~crc;
}

/* Safer bounds handling than the Windows validator's unchecked header read. */
int fpc_template_validate(const uint8_t *data, size_t size,
                          uint32_t *version, size_t *blocks) {
    if (!data || size<8 || size>INT32_MAX || le32(data+4)!=size) return -1;
    size_t offset=8, count=0;
    while (offset<size) {
        size_t remaining=size-offset;
        if (remaining<12) return -1;
        uint32_t length=le32(data+offset+4);
        if (length<12 || length>remaining) return -1;
        if (fpc_crc32(data+offset, length-4)!=le32(data+offset+length-4)) return -1;
        offset+=length;
        ++count;
    }
    if (version) *version=((uint32_t)data[0] | (uint32_t)data[1]<<8)<<16 |
                          (uint32_t)data[2] | (uint32_t)data[3]<<8;
    if (blocks) *blocks=count;
    return 0;
}

/* 18005a2d0: only values 0 and 255 count as saturated. */
int fpc_saturation_quality(const uint8_t *pixels, size_t count) {
    if (!pixels || !count || count>INT_MAX/1000) return -1;
    size_t saturated=0;
    for (size_t i=0; i<count; ++i)
        saturated += pixels[i]==0 || pixels[i]==255;
    return 1000-(int)(saturated*1000/count);
}

/* Explicit arithmetic right shift (floor division), portable across C targets. */
static int64_t shift_floor(int64_t value, unsigned bits) {
    int64_t divisor=INT64_C(1)<<bits;
    return value>=0 ? value/divisor : -((-value+divisor-1)/divisor);
}

/* 1800496c0. Widened intermediates avoid C signed-overflow UB.
 * Validated domain: original signed 32-bit intermediate arithmetic fits. */
int fpc_score_remap(int raw_score, int probe_features, int overlap,
                    const int16_t coeff[4], int maximum) {
    if (!coeff || maximum<0) return -1;
    int64_t score=0;
    if (raw_score>0) {
        score=shift_floor((int64_t)coeff[3]*overlap,10);
        score+=(int64_t)coeff[1]*raw_score;
        score+=(int64_t)coeff[2]*probe_features+coeff[0];
        score=shift_floor(score,7);
    }
    if (score<0) score=0;
    if (score>maximum) score=maximum;
    return (int)score;
}

/* 180066980: forward/reversed patches produce the two descriptor halves. */
int fpc_project_descriptor(const uint8_t *patch, size_t pixels,
                           const int16_t *weights, size_t weight_count,
                           uint8_t *descriptor, size_t descriptor_bytes) {
    if (!patch || !weights || !descriptor || !pixels || !descriptor_bytes ||
        descriptor_bytes%2 || descriptor_bytes>16 ||
        pixels>SIZE_MAX/(descriptor_bytes*4) ||
        weight_count!=pixels*descriptor_bytes*4) return -1;
    size_t projections=descriptor_bytes*4;
    for (size_t byte=0; byte<descriptor_bytes/2; ++byte) {
        uint8_t forward=0, reverse=0;
        for (unsigned bit=0; bit<8; ++bit) {
            int64_t a=0, b=0;
            for (size_t pixel=0; pixel<pixels; ++pixel) {
                int16_t weight=weights[pixel*projections+byte*8+bit];
                a+=(int64_t)weight*patch[pixel];
                b+=(int64_t)weight*patch[pixels-1-pixel];
            }
            if (a>0) forward|=(uint8_t)(1u<<bit);
            if (b>0) reverse|=(uint8_t)(1u<<bit);
        }
        descriptor[byte]=forward;
        descriptor[byte+descriptor_bytes/2]=reverse;
    }
    return 0;
}

static unsigned popcount32(uint32_t value) {
    value-= (value>>1)&UINT32_C(0x55555555);
    value=(value&UINT32_C(0x33333333))+((value>>2)&UINT32_C(0x33333333));
    return (((value+(value>>4))&UINT32_C(0x0f0f0f0f))*UINT32_C(0x01010101))>>24;
}

/* 1800720c0. Not ordinary Hamming distance: half-swap invariance. */
unsigned fpc_descriptor_distance32(uint32_t first, uint32_t second) {
    unsigned a=popcount32(first^second);
    unsigned b=popcount32(((first<<16)|(first>>16))^second);
    return a<b ? a : b;
}

static int64_t signed_u32(uint32_t value) {
    return value<=INT32_MAX ? (int64_t)value : (int64_t)value-INT64_C(4294967296);
}

unsigned fpc_descriptor_distance128(const uint8_t first[16], const uint8_t second[16]) {
    unsigned normal=0,rotated=0;
    for (size_t i=0;i<16;i+=4) {
        normal+=popcount32(le32(first+i)^le32(second+i));
        rotated+=popcount32(le32(first+i)^le32(second+(i^8)));
    }
    return normal<rotated ? normal : rotated;
}

int fpc_mutual_candidates(const uint8_t *matrix, size_t first_count,
                           size_t second_count, size_t stride, unsigned threshold,
                           uint16_t first_offset, uint16_t second_offset,
                           fpc_candidate *output, size_t capacity, size_t *count) {
    if (!count || first_count>32767 || second_count>32767 ||
        stride<second_count || capacity<first_count ||
        (first_count && second_count && (!matrix || !output)) ||
        (first_count && stride>SIZE_MAX/first_count)) return -1;
    *count=0;
    if (!first_count || !second_count) return 0;
    uint16_t *nearest=malloc(second_count*sizeof(*nearest));
    if (!nearest) return -1;
    for (size_t j=0;j<second_count;++j) {
        unsigned best=255; nearest[j]=0;
        for (size_t i=0;i<first_count;++i) {
            unsigned d=matrix[i*stride+j];
            if (d<best) {best=d;nearest[j]=(uint16_t)i;}
        }
    }
    for (size_t i=0;i<first_count;++i) {
        unsigned best=255; size_t jbest=0;
        for (size_t j=0;j<second_count;++j) {
            unsigned d=matrix[i*stride+j];
            if (d<best) {best=d;jbest=j;}
        }
        if (nearest[jbest]==i && best<threshold) {
            fpc_candidate *p=output+(*count)++;
            p->first=(uint16_t)(i+first_offset);
            p->second=(uint16_t)(jbest+second_offset);
            p->distance=(uint16_t)best;p->flag=0;
        }
    }
    free(nearest);return 0;
}

/* 18004c270. The original assumes all four neighbors exist. */
int fpc_sample_affine_q15(const uint8_t *source, size_t width, size_t height,
                          size_t stride, uint8_t *patch, size_t patch_width,
                          size_t patch_height, const int32_t affine[6]) {
    if (!source || !patch || !affine || width<2 || height<2 || stride<width ||
        !patch_width || !patch_height || height>SIZE_MAX/stride ||
        patch_height>SIZE_MAX/patch_width) return -1;
    /* Validate all neighborhoods before modifying destination. */
    for (unsigned pass=0; pass<2; ++pass) {
        uint32_t rowx=(uint32_t)affine[2], rowy=(uint32_t)affine[5];
        for (size_t py=0; py<patch_height; ++py) {
            uint32_t qx=rowx, qy=rowy;
            for (size_t px=0; px<patch_width; ++px) {
                int64_t ix=shift_floor(signed_u32(qx),15);
                int64_t iy=shift_floor(signed_u32(qy),15);
                if (ix<0 || iy<0 || (uint64_t)ix>=width-1 || (uint64_t)iy>=height-1) return -1;
                if (pass) {
                    uint32_t fx=qx&0x7fff, fy=qy&0x7fff;
                    uint32_t w00=((32768-fx)*(32768-fy))>>15;
                    uint32_t w10=(fx*(32768-fy))>>15;
                    uint32_t w01=((32768-fx)*fy)>>15;
                    uint32_t w11=(fx*fy)>>15;
                    const uint8_t *pixel=source+(size_t)iy*stride+(size_t)ix;
                    patch[py*patch_width+px]=(uint8_t)((pixel[0]*w00+pixel[1]*w10+
                                                       pixel[stride]*w01+pixel[stride+1]*w11)>>15);
                }
                qx+=(uint32_t)affine[0]; qy+=(uint32_t)affine[3];
            }
            rowx+=(uint32_t)affine[1]; rowy+=(uint32_t)affine[4];
        }
    }
    return 0;
}

/* 1800453a0. Compile with floating-point contraction disabled for fidelity. */
int fpc_sincos_recovered(float radians, float *cosine, float *sine) {
    const float pi=0x1.921fb6p+1f, tau=0x1.921fb6p+2f;
    if (!cosine || !sine || !(radians>=-10000.0f && radians<=10000.0f)) return -1;
    float quotient=radians/tau;
    int turns=(int)quotient;
    if (quotient<0.0f) --turns;
    float angle=radians-((float)turns+(float)turns)*pi;
    float sign=1.0f;
    if (angle>pi) { angle+=-pi; sign=-1.0f; }
    float a=sign, b=0.0f;
    if (angle>0x1.921fb6p+0f) { angle+=-0x1.921fb6p+0f; a=-0.0f; b=sign; }
    angle+=-0x1.921fb6p-1f;
    float u=(a-b)*0x1.6a09e6p-1f;
    float v=(b+b)*0x1.6a09e6p-1f+u;
    float square=angle*angle;
    float c=(((square*0x1.a01a02p-16f-0x1.6c16c2p-10f)*square+
               0x1.555556p-5f)*square-0.5f)*square+1.0f;
    float s=((((square*0x1.71de3ap-19f-0x1.a01a02p-13f)*square+
                0x1.111112p-7f)*square-0x1.555556p-3f)*square+1.0f)*angle;
    *cosine=c*u-s*v; *sine=c*v+s*u;
    return 0;
}

/* 180066770; quantization occurs once per coefficient, not per pixel. */
static int sample_descriptor_roi(const uint8_t *source, size_t width,
                                size_t height, size_t stride, uint8_t *patch,
                                unsigned side, unsigned source_span,
                                uint8_t x, uint8_t y, float degrees, unsigned origin_x, unsigned origin_y) {
    if (side<2 || side>25 || source_span<2 || source_span>25) return -1;
    float c, s;
    if (fpc_sincos_recovered(degrees*0x1.1df46ap-6f,&c,&s)) return -1;
    float half=(float)((source_span-1)/2);
    float scale=(float)(source_span-1)/(float)(side-1);
    float transform[6]={scale*c, -(scale*s), (float)x-(c-s)*half,
                        scale*s, scale*c, (float)y-(c+s)*half};
    int32_t fixed[6];
    for (unsigned i=0; i<6; ++i) fixed[i]=(int32_t)(transform[i]*32768.0f);
    fixed[2]+=(int32_t)(origin_x*32768u);
    fixed[5]+=(int32_t)(origin_y*32768u);
    return fpc_sample_affine_q15(source,width,height,stride,patch,side,side,fixed);
}

int fpc_sample_descriptor_patch(const uint8_t *source, size_t width,
                                size_t height, size_t stride, uint8_t *patch,
                                unsigned side, unsigned source_span,
                                uint8_t x, uint8_t y, float degrees) {
    return sample_descriptor_roi(source,width,height,stride,patch,side,source_span,x,y,degrees,0,0);
}

/* Radius-three coordinate table at 180087eb0. */
static const int8_t circle_offsets[16][2]={
    {0,3},{1,3},{2,2},{3,1},{3,0},{3,-1},{2,-2},{1,-3},
    {0,-3},{-1,-3},{-2,-2},{-3,-1},{-3,0},{-3,1},{-2,2},{-1,3}
};

/* Scalar equivalent of 180062260's arc test and 180062820's score.
 * Maximum threshold supporting nine consecutive pixels, less one. */
static uint8_t circle_response(const uint8_t *image, size_t stride,
                                size_t x, size_t y, unsigned threshold) {
    int difference[16];
    int center=image[y*stride+x];
    for (unsigned k=0; k<16; ++k) {
        size_t nx=(size_t)((int64_t)x+circle_offsets[k][0]);
        size_t ny=(size_t)((int64_t)y+circle_offsets[k][1]);
        difference[k]=center-image[ny*stride+nx];
    }
    int strongest=0;
    for (unsigned start=0; start<16; ++start) {
        int darker=255, brighter=255;
        for (unsigned k=0; k<9; ++k) {
            int value=difference[(start+k)&15];
            if (value<darker) darker=value;
            if (-value<brighter) brighter=-value;
        }
        if (darker>strongest) strongest=darker;
        if (brighter>strongest) strongest=brighter;
    }
    return strongest>(int)threshold ? (uint8_t)(strongest-1) : 0;
}

/* 180061210 branch 0 followed by 180061ac0 strict nonmax selection.
 * Safe API calculates only interior responses; original relies on mask/padding. */
int fpc_detect_circle9(const uint8_t *image, size_t width, size_t height,
                        size_t stride, const uint8_t *mask, size_t mask_stride,
                        unsigned threshold, unsigned border, uint8_t *responses,
                        fpc_keypoint *points, size_t capacity, size_t *count) {
    if (!image || !mask || !responses || !count || (!points && capacity) ||
        width<7 || height<7 || width>256 || height>256 || stride<width ||
        mask_stride<width || height>SIZE_MAX/stride || height>SIZE_MAX/mask_stride ||
        threshold>255 || border<3) return -1;
    *count=0;
    for (size_t i=0; i<width*height; ++i) responses[i]=0;
    for (size_t y=3; y<height-3; ++y)
        for (size_t x=3; x<width-3; ++x)
            if (mask[y*mask_stride+x]==255)
                responses[y*width+x]=circle_response(image,stride,x,y,threshold);
    if (border>=width || border>=height) return 0;
    for (size_t y=border; y<height-border; ++y) {
        for (size_t x=border; x<width-border; ++x) {
            uint8_t response=responses[y*width+x];
            if (!mask[y*mask_stride+x] || *count>=capacity) continue;
            int maximum=1;
            for (int dy=-1; dy<=1; ++dy)
                for (int dx=-1; dx<=1; ++dx) {
                    if (!dx && !dy) continue;
                    size_t ny=(size_t)((int64_t)y+dy), nx=(size_t)((int64_t)x+dx);
                    if (responses[ny*width+nx]>=response) maximum=0;
                }
            if (maximum) {
                points[*count]=(fpc_keypoint){(uint8_t)x,(uint8_t)y,0,(float)response};
                ++*count;
            }
        }
    }
    return 0;
}

/* 180061c90 scalar/SIMD score, scale at 180087a74 and 180087f40. */
int fpc_harris_scores(const int16_t *xx, const int16_t *yy, const int16_t *xy,
                       size_t count, float k, float *scores) {
    if (!xx || !yy || !xy || !scores || !(k>=0.0f && k<=1.0f)) return -1;
    for (size_t i=0; i<count; ++i) {
        int32_t a=xx[i], b=yy[i], c=xy[i], trace=a+b;
        uint32_t determinant=(uint32_t)((int64_t)a*b-(int64_t)c*c);
        uint32_t trace_square=(uint32_t)trace*(uint32_t)trace;
        scores[i]=((float)signed_u32(determinant)-(float)signed_u32(trace_square)*k)*0.015625f;
    }
    return 0;
}

/* 180062a20; no positivity or explicit response threshold in this selector. */
int fpc_select_float_maxima(const float *scores, size_t width, size_t height,
                             size_t stride, const uint8_t *mask, size_t mask_stride,
                             unsigned border, fpc_keypoint *points,
                             size_t capacity, size_t *count) {
    if (!scores || !mask || !count || (!points && capacity) || !width || !height ||
        width>256 || height>256 || stride<width || mask_stride<width ||
        height>SIZE_MAX/stride || height>SIZE_MAX/mask_stride || border<1) return -1;
    *count=0;
    if (border>=width || border>=height) return 0;
    for (size_t y=border; y<height-border; ++y)
        for (size_t x=border; x<width-border; ++x) {
            if (!mask[y*mask_stride+x] || *count>=capacity) continue;
            float value=scores[y*stride+x];
            int maximum=1;
            for (int dy=-1; dy<=1; ++dy)
                for (int dx=-1; dx<=1; ++dx) {
                    if (!dx && !dy) continue;
                    size_t ny=(size_t)((int64_t)y+dy), nx=(size_t)((int64_t)x+dx);
                    if (!(scores[ny*stride+nx]<value)) maximum=0;
                }
            if (maximum) {
                points[*count]=(fpc_keypoint){(uint8_t)x,(uint8_t)y,0,value};
                ++*count;
            }
        }
    return 0;
}

/* 1800459c0: assembly confirms exponent-field adjustment absent in decompilation. */
static float recovered_exp(float input) {
    float value=input;
    if (value>0x1.62e426p+6f) value=0x1.62e426p+6f;
    if (value<-0x1.5d5894p+6f) value=-0x1.5d5894p+6f;
    float quotient=value/0x1.62e430p-1f;
    int exponent=(int)(quotient<=0.0f ? quotient-0.5f : quotient+0.5f);
    float remainder=value-(float)exponent*0x1.62e430p-1f;
    float square=remainder*remainder;
    float denominator=(((((square*0x1.637698p-25f-0x1.bbd41cp-20f)*square+
                           0x1.1566aap-14f)*square-0x1.6c16c2p-9f)*square+
                           0x1.555556p-3f)*square+2.0f)-remainder;
    float result=(remainder+remainder)/denominator+1.0f;
    if (result!=0.0f) {
        uint32_t bits;
        memcpy(&bits,&result,sizeof(bits));
        bits+=(uint32_t)exponent<<23;
        memcpy(&result,&bits,sizeof(result));
    }
    return result;
}

static int16_t signed_u16(uint16_t value) {
    return (int16_t)(value<=INT16_MAX ? (int32_t)value : (int32_t)value-65536);
}

#include "sqrt_seed.h"

void fpc_loaded_collection_destroy(fpc_loaded_collection *collection) {
    if (!collection) return;
    for (size_t i=0;i<collection->count;++i) fpc_loaded_capture_destroy(collection->captures+i);
    free(collection->captures);memset(collection,0,sizeof(*collection));
}

int fpc_classify_raw_pixels(const uint8_t *image, size_t width, size_t height,
                             size_t image_stride, const uint16_t *defective_indices,
                             size_t defective_count, uint8_t *flags, size_t flags_stride) {
    if (!image || !flags || !width || !height || image_stride<width || flags_stride<width ||
        height>SIZE_MAX/width || height>SIZE_MAX/image_stride || height>SIZE_MAX/flags_stride ||
        (defective_count && !defective_indices)) return -1;
    size_t count=width*height;
    for (size_t i=0;i<defective_count;++i) if (defective_indices[i]>=count) return -1;
    for (size_t y=0;y<height;++y) for (size_t x=0;x<width;++x) {
        uint8_t pixel=image[y*image_stride+x];
        flags[y*flags_stride+x]=pixel==0?1:pixel==255?16:2;
    }
    for (size_t i=0;i<defective_count;++i)
        flags[(defective_indices[i]/width)*flags_stride+defective_indices[i]%width]=4;
    return 0;
}

static void defect_neighbor_sum(const float *image, size_t width, size_t height,
                                 const uint8_t *excluded, size_t index, size_t radius,
                                 size_t *count, float *sum) {
    size_t x=index%width,y=index/width,x0=x>radius?x-radius:0,y0=y>radius?y-radius:0;
    size_t x1=x+radius<width?x+radius:width-1,y1=y+radius<height?y+radius:height-1;
    *count=0;*sum=0.0f;
    for (size_t row=y0;row<=y1;++row) for (size_t col=x0;col<=x1;++col) {
        size_t at=row*width+col;
        if (!excluded[at]) {++*count;*sum=image[at]+*sum;}
    }
}

int fpc_fill_saturated_pixels(float *image, size_t width, size_t height,
                               const uint8_t *source_flags, uint8_t *working_flags) {
    if (!image || !source_flags || !working_flags || !width || !height ||
        height>SIZE_MAX/width) return -1;
    size_t pixels=width*height;
    uint8_t *excluded=malloc(pixels);if (!excluded) return 2;
    for (size_t i=0;i<pixels;++i) excluded[i]=(working_flags[i]&2)==0;
    for (size_t i=0;i<pixels;++i) if (source_flags[i]&0x11) {
        for (unsigned window=3;window<=5;window+=2) {
            if (working_flags[i]==8) break;
            size_t neighbors=0;float sum=0.0f;
            defect_neighbor_sum(image,width,height,excluded,i,window/2,&neighbors,&sum);
            if (neighbors && (window!=5 || neighbors>5)) {
                image[i]=sum/(float)neighbors;working_flags[i]=8;excluded[i]=1;
            }
        }
    }
    free(excluded);return 0;
}

static int correct_defective_pixels_mode(float *image, size_t width, size_t height,
                                  const uint16_t *indices, size_t count,
                                  uint16_t maximum_count, int require_all, unsigned mode) {
    if (!image || !width || !height || width>INT32_MAX || height>INT32_MAX ||
        height>SIZE_MAX/width || count>UINT16_MAX || (count && !indices)) return -1;
    size_t pixels=width*height;
    for (size_t i=0;i<count;++i) if (indices[i]>=pixels) return -1;
    if (!count) return 0;
    if (require_all && count>maximum_count) return 1001;
    uint8_t *excluded=calloc(pixels,1),*resolved=calloc(count,1);
    if (!excluded || !resolved) {free(excluded);free(resolved);return 2;}
    for (size_t i=0;i<count;++i) excluded[indices[i]]=1;
    for (unsigned window=3;window<=5;window+=2) for (size_t i=0;i<count;++i) if (!resolved[i]) {
        size_t neighbors=0;float sum=0.0f;
        defect_neighbor_sum(image,width,height,excluded,indices[i],window/2,&neighbors,&sum);
        if (neighbors && (window!=5 || neighbors>5)) {
            image[indices[i]]=sum/(float)neighbors;resolved[i]=1;
        }
    }
    for (unsigned window=5;window<=7;window+=2) for (size_t i=0;i<count;++i) if (!resolved[i]) {
        size_t x=indices[i]%width,y=indices[i]/width;
        if (x>1 && x+2<width && y>1 && y+2<height) continue;
        size_t neighbors=0;float sum=0.0f;
        defect_neighbor_sum(image,width,height,excluded,indices[i],window/2,&neighbors,&sum);
        if (neighbors) {image[indices[i]]=sum/(float)neighbors;resolved[i]=1;}
    }
    if (mode==4) for (unsigned pass=0;pass<maximum_count;++pass) {
        int unresolved=0;memset(excluded,0,pixels);
        for (size_t i=0;i<count;++i) if (!resolved[i]) {excluded[indices[i]]=1;unresolved=1;}
        if (!unresolved) break;
        /* Newly filled entries remain excluded until the next complete pass. */
        for (size_t i=0;i<count;++i) if (!resolved[i]) {
            size_t neighbors=0;float sum=0.0f;
            defect_neighbor_sum(image,width,height,excluded,indices[i],2,&neighbors,&sum);
            if (neighbors>5) {image[indices[i]]=sum/(float)neighbors;resolved[i]=255;}
        }
        for (size_t i=0;i<count;++i) if (resolved[i]==255) resolved[i]=1;
    }
    int status=0;
    if (require_all) for (size_t i=0;i<count;++i) if (!resolved[i]) {status=1001;break;}
    free(excluded);free(resolved);return status;
}

int fpc_correct_defective_pixels(float *image, size_t width, size_t height,
                                  const uint16_t *indices, size_t count,
                                  uint16_t maximum_count, int require_all) {
    return correct_defective_pixels_mode(image,width,height,indices,count,maximum_count,require_all,0);
}

int fpc_process_raw_pixel_defects(float *image, uint8_t *flags, size_t width, size_t height,
                                   const uint16_t *indices, size_t count, unsigned mode,
                                   uint16_t maximum_count, int require_all) {
    if (mode>4) return 105;
    if (!image || !width || !height || height>SIZE_MAX/width || count>UINT16_MAX ||
        (count && !indices)) return -1;
    size_t pixels=width*height;
    for (size_t i=0;i<count;++i) if (indices[i]>=pixels) return -1;
    if (!mode || mode==4) return correct_defective_pixels_mode(image,width,height,indices,count,maximum_count,require_all,mode);
    /* Original writes flags by list ordinal, so its count must fit flag storage. */
    if (!flags || count>pixels) return -1;
    uint8_t *working=malloc(pixels);if (!working) return 2;
    memcpy(working,flags,pixels);
    int status=fpc_fill_saturated_pixels(image,width,height,flags,working);
    if (status) {free(working);return status;}
    if (mode<=2) for (size_t i=0;i<pixels;++i) {
        if (working[i]&1) image[i]=0.0f;
        else if (working[i]&16) image[i]=255.0f;
    }
    status=fpc_correct_defective_pixels(image,width,height,indices,count,maximum_count,require_all);
    if (status) {free(working);return status;}
    for (size_t i=0;i<count;++i) {
        if (!(image[indices[i]]>0.0f)) working[i]=1;
        else if (image[indices[i]]>=255.0f) working[i]=16;
    }
    memcpy(flags,working,pixels);
    if (mode==1) {
        memset(working,2,pixels);status=fpc_fill_saturated_pixels(image,width,height,flags,working);
    }
    free(working);return status;
}

int fpc_loaded_collection_take_capture(fpc_loaded_collection *collection,
                                        fpc_loaded_capture *incoming, size_t index) {
    if (!collection || !incoming || collection->count>collection->capacity ||
        index>=collection->capacity || index>collection->count ||
        (collection->count && !collection->captures)) return 1;
    for (size_t i=0;i<collection->count;++i)
        if (incoming==collection->captures+i ||
            (incoming->storage && incoming->storage==collection->captures[i].storage)) return 1;
    if (index==collection->count) {
        if (collection->count>=SIZE_MAX/sizeof(*collection->captures)) return 1;
        fpc_loaded_capture *captures=realloc(collection->captures,(collection->count+1)*sizeof(*captures));
        if (!captures) return 2;
        collection->captures=captures;collection->captures[index]=*incoming;++collection->count;
    } else {
        fpc_loaded_capture_destroy(collection->captures+index);collection->captures[index]=*incoming;
    }
    memset(incoming,0,sizeof(*incoming));return 0;
}

static int checked_block(const uint8_t *data,size_t size,uint32_t tag,size_t *length) {
    if (size<12 || le32(data)!=tag) return 140;
    uint32_t bytes=le32(data+4);
    if (bytes<12 || bytes>size || fpc_crc32(data,bytes-4)!=le32(data+bytes-4)) return 140;
    *length=bytes;return 0;
}

int fpc_collection_load_default(const uint8_t *data, size_t size,
                                  fpc_loaded_collection *output, size_t *consumed) {
    if (!data || !output || !consumed) return 140;
    size_t length=0;
    if (checked_block(data,size,UINT32_C(1540161792),&length) || length!=24 || le32(data+8)!=0x0ce1) return 140;
    uint32_t count=le32(data+12),capacity=le32(data+16);
    if (!count || count>80 || count>capacity || capacity>65535) return 140;
    fpc_loaded_collection result={0};result.count=count;result.capacity=capacity;
    result.captures=calloc(count,sizeof(*result.captures));if (!result.captures) return 2;
    size_t offset=24;
    for (size_t i=0;i<count;++i) {
        int status=checked_block(data+offset,size-offset,UINT32_C(1540162048)+(uint32_t)i,&length);
        if (!status) status=fpc_capture_load_payload(data+offset+8,length-12,0x0ce1,result.captures+i);
        if (status) {fpc_loaded_collection_destroy(&result);return status;}
        offset+=length;
    }
    *output=result;*consumed=offset;return 0;
}

int fpc_collection_serialize_default(const fpc_capture_payload_view *captures,
                                       size_t count, uint32_t capture_capacity,
                                       uint8_t *output, size_t capacity, size_t *written) {
    if (!written || count>80 || count>capture_capacity || (count && !captures)) return -1;
    size_t sizes[80],total=24;
    for (size_t i=0;i<count;++i) {
        if (fpc_capture_payload(captures+i,0x0ce1,NULL,0,sizes+i) || sizes[i]>UINT32_MAX-12 || total>SIZE_MAX-sizes[i]-12) return -1;
        total+=sizes[i]+12;
    }
    *written=total;if (!output) return 0;
    if (capacity<total) return -1;
    store_le32(output,UINT32_C(1540161792));store_le32(output+4,24);
    store_le32(output+8,0x0ce1);store_le32(output+12,(uint32_t)count);store_le32(output+16,capture_capacity);
    store_le32(output+20,fpc_crc32(output,20));
    size_t offset=24;
    for (size_t i=0;i<count;++i) {
        store_le32(output+offset,UINT32_C(1540162048)+(uint32_t)i);
        store_le32(output+offset+4,(uint32_t)(sizes[i]+12));size_t size=0;
        if (fpc_capture_payload(captures+i,0x0ce1,output+offset+8,sizes[i],&size)) return -1;
        store_le32(output+offset+8+size,fpc_crc32(output+offset,size+8));offset+=size+12;
    }
    return 0;
}

void fpc_loaded_capture_destroy(fpc_loaded_capture *capture) {
    if (!capture) return;
    free(capture->storage);memset(capture,0,sizeof(*capture));
}

int fpc_capture_load_payload(const uint8_t *data, size_t size, uint16_t flags,
                               fpc_loaded_capture *output) {
    if (!data || !output || size<4) return 140;
    uint32_t n=le32(data);if (n>32767) return 140;
    fpc_loaded_capture result={0};result.view.count=n;
    if (!(flags&0x400)) {if (size!=4) return 140;*output=result;return 0;}
    if (size<8) return 140;
    fpc_capture_payload_view *v=&result.view;v->mode=data[4];v->descriptor_bytes=data[5];v->levels=data[6];v->table_width=data[7];
    size_t extra=v->table_width?v->table_width-1u:0,words=(size_t)v->levels*(5+extra);
    size_t coordinate_bytes=(size_t)n*((flags&0x20)?2:8),score_bytes=(flags&4)?4u*n:0,angle_bytes=(flags&2)?4u*n:0;
    size_t descriptor_bytes=(flags&0x800)?(size_t)n*v->descriptor_bytes:0,membership_bytes=(flags&0x80)?((size_t)n+7)/8:0;
    size_t needed=8+2*words+coordinate_bytes+score_bytes+angle_bytes+descriptor_bytes+membership_bytes;
    if (size!=needed) return 140;
    uint32_t sum=0;size_t offset=8;
    for (size_t l=0;l<v->levels;++l) {uint16_t count=(uint16_t)(data[offset]|(uint16_t)data[offset+1]<<8);if (count>32767) return 140;sum+=count;offset+=2*(5+extra);}
    if (sum!=n) return 140;
    /* Numeric arrays precede byte arrays; all uint32 accesses stay aligned. */
    size_t numeric_bytes=2*words;numeric_bytes=(numeric_bytes+3)&~(size_t)3;
    if (!(flags&0x20)) numeric_bytes+=coordinate_bytes;
    numeric_bytes+=score_bytes+angle_bytes;
    size_t allocation=numeric_bytes+((flags&0x20)?coordinate_bytes:0)+descriptor_bytes+membership_bytes;
    result.storage=calloc(allocation?allocation:1,1);if (!result.storage) return 2;
    uint8_t *base=result.storage;uint16_t *fields=(uint16_t *)base,*extras=fields+5*v->levels;
    v->level_fields=fields;v->level_extra=extras;offset=8;
    for (size_t l=0;l<v->levels;++l) for (size_t j=0;j<5+extra;++j) {
        uint16_t value=(uint16_t)(data[offset]|(uint16_t)data[offset+1]<<8);offset+=2;
        if (j<5) fields[5*l+j]=value;else extras[extra*l+j-5]=value;
    }
    size_t pos=(2*words+3)&~(size_t)3;
    if (flags&0x20) {v->compact_coordinates=coordinate_bytes?base+numeric_bytes:NULL;if (coordinate_bytes) memcpy(base+numeric_bytes,data+offset,coordinate_bytes);offset+=coordinate_bytes;}
    uint32_t *arrays[3];size_t lengths[3]={(flags&0x20)?0:2u*n,(flags&4)?n:0,(flags&2)?n:0};
    for (size_t a=0;a<3;++a) {
        arrays[a]=(uint32_t *)(base+pos);
        for (size_t i=0;i<lengths[a];++i) {arrays[a][i]=le32(data+offset);offset+=4;}
        pos+=4*lengths[a];
    }
    v->coordinates=lengths[0]?arrays[0]:NULL;v->scores=lengths[1]?arrays[1]:NULL;v->angles=lengths[2]?arrays[2]:NULL;
    pos=numeric_bytes+((flags&0x20)?coordinate_bytes:0);v->descriptors=descriptor_bytes?base+pos:NULL;
    if (descriptor_bytes) memcpy(base+pos,data+offset,descriptor_bytes);
    pos+=descriptor_bytes;offset+=descriptor_bytes;v->membership=membership_bytes?base+pos:NULL;
    if (membership_bytes) memcpy(base+pos,data+offset,membership_bytes);
    *output=result;return 0;
}

void fpc_loaded_groups_destroy(fpc_loaded_groups *groups) {
    if (!groups) return;
    free(groups->storage);memset(groups,0,sizeof(*groups));
}

int fpc_group_load_payload(const uint8_t *data, size_t size, fpc_loaded_groups *output) {
    if (!data || !output || size<4) return 140;
    uint16_t count=(uint16_t)(data[0]|(uint16_t)data[1]<<8),gc=(uint16_t)(data[2]|(uint16_t)data[3]<<8);
    if (count>32767 || size!=4+40u*(size_t)count) return 140;
    fpc_loaded_groups result={0};result.count=count;memcpy(&result.group_count,&gc,2);
    if (count) {
        result.storage=malloc(40u*count);if (!result.storage) return 2;
        result.matrix_bits=result.storage;
        result.groups=(int16_t *)(result.matrix_bits+9u*count);
        result.roots=(uint16_t *)(result.groups+count);
    }
    size_t offset=4;
    for (size_t i=0;i<count;++i) {
        uint16_t group=(uint16_t)(data[offset]|(uint16_t)data[offset+1]<<8);
        memcpy(&result.groups[i],&group,2);
        result.roots[i]=(uint16_t)(data[offset+2]|(uint16_t)data[offset+3]<<8);offset+=4;
        for (size_t j=0;j<9;++j) {result.matrix_bits[9*i+j]=le32(data+offset);offset+=4;}
    }
    *output=result;return 0;
}

int fpc_group_payload(size_t count, int16_t group_count, const int16_t *groups,
                       const uint16_t *roots, const uint32_t *matrix_bits,
                       uint8_t *output, size_t capacity, size_t *written) {
    if (!written || count>32767 || (count && (!groups || !roots || !matrix_bits))) return -1;
    *written=4+40*count;if (!output) return 0;
    if (capacity<*written) return -1;
    uint16_t header[2]={(uint16_t)count,(uint16_t)group_count};
    for (size_t i=0;i<2;++i) {output[2*i]=(uint8_t)header[i];output[2*i+1]=(uint8_t)(header[i]>>8);}
    size_t offset=4;
    for (size_t i=0;i<count;++i) {
        uint16_t pair[2]={(uint16_t)groups[i],roots[i]};
        for (size_t j=0;j<2;++j) {output[offset++]=(uint8_t)pair[j];output[offset++]=(uint8_t)(pair[j]>>8);}
        for (size_t j=0;j<9;++j) for (unsigned k=0;k<4;++k)
            output[offset++]=(uint8_t)(matrix_bits[9*i+j]>>(8*k));
    }
    return 0;
}

int fpc_capture_payload(const fpc_capture_payload_view *view, uint16_t flags,
                          uint8_t *output, size_t capacity, size_t *written) {
    if (!view || !written || view->count>32767) return -1;
    size_t n=view->count,extra=view->table_width?view->table_width-1u:0;
    size_t size=4;
    if (flags&0x400) {
        if ((view->levels && !view->level_fields) || (view->levels && extra && !view->level_extra) ||
            (n && ((flags&0x20)?!view->compact_coordinates:!view->coordinates)) ||
            (n && (flags&4) && !view->scores) || (n && (flags&2) && !view->angles) ||
            (n && view->descriptor_bytes && (flags&0x800) && !view->descriptors) ||
            (n && (flags&0x80) && !view->membership)) return -1;
        size=8+(size_t)view->levels*(10+2*extra)+n*((flags&0x20)?2u:8u);
        if (flags&4) size+=4*n;
        if (flags&2) size+=4*n;
        if (flags&0x800) size+=n*view->descriptor_bytes;
        if (flags&0x80) size+=(n+7)/8;
    }
    *written=size;if (!output) return 0;
    if (capacity<size) return -1;
    for (unsigned j=0;j<4;++j) output[j]=(uint8_t)(view->count>>(8*j));
    if (!(flags&0x400)) return 0;
    output[4]=view->mode;output[5]=view->descriptor_bytes;output[6]=view->levels;output[7]=view->table_width;
    size_t offset=8;
    for (size_t l=0;l<view->levels;++l) for (size_t j=0;j<5+extra;++j) {
        uint16_t value=j<5?view->level_fields[5*l+j]:view->level_extra[extra*l+j-5];
        output[offset++]=(uint8_t)value;output[offset++]=(uint8_t)(value>>8);
    }
    if (flags&0x20) {if (n) memcpy(output+offset,view->compact_coordinates,2*n);offset+=2*n;}
    const uint32_t *arrays[3]={view->coordinates,view->scores,view->angles};
    size_t lengths[3]={(flags&0x20)?0:2*n,(flags&4)?n:0,(flags&2)?n:0};
    for (size_t a=0;a<3;++a) for (size_t i=0;i<lengths[a];++i)
        for (unsigned j=0;j<4;++j) output[offset++]=(uint8_t)(arrays[a][i]>>(8*j));
    if (flags&0x800) {size_t bytes=n*view->descriptor_bytes;if (bytes) memcpy(output+offset,view->descriptors,bytes);offset+=bytes;}
    if (flags&0x80) {size_t bytes=(n+7)/8;if (bytes) memcpy(output+offset,view->membership,bytes);}
    return 0;
}

void fpc_loaded_pair_destroy(fpc_loaded_pair *pair) {
    if (!pair) return;
    free(pair->pairs);memset(pair,0,sizeof(*pair));
}

int fpc_pair_load_payload(const uint8_t *data, size_t size, uint16_t flags,
                            fpc_loaded_pair *output) {
    if (!data || !output || size<17 || !(flags&0x1000)) return 140;
    uint32_t count=le32(data),inliers=le32(data+4);
    size_t stride=4+((flags&0x4000)?2u:0u)+((flags&0x8000)?1u:0u);
    if (count>32767 || inliers>2048 || count>(SIZE_MAX-17)/stride || size!=17+(size_t)count*stride) return 140;
    fpc_loaded_pair result={0};result.count=count;result.inliers=inliers;result.success=data[8];
    for (size_t i=0;i<4;++i) {uint16_t value=(uint16_t)(data[9+2*i]|(uint16_t)data[10+2*i]<<8);memcpy(&result.transform[i],&value,2);}
    if (count) {result.pairs=calloc(count,sizeof(*result.pairs));if (!result.pairs) return 2;}
    size_t offset=17;
    for (size_t i=0;i<count;++i) {
        uint16_t values[3]={0,0,0};size_t words=(flags&0x4000)?3:2;
        for (size_t j=0;j<words;++j) {values[j]=(uint16_t)(data[offset]|(uint16_t)data[offset+1]<<8);offset+=2;}
        result.pairs[i]=(fpc_candidate){values[0],values[1],values[2],
            (flags&0x8000)?data[offset++]:((flags&0x2000)?1:0),0};
    }
    *output=result;return 0;
}

int fpc_pair_payload(const fpc_candidate *pairs, size_t count, uint32_t inliers,
                       uint8_t success, const int16_t transform[4], uint16_t flags,
                       uint8_t *output, size_t capacity, size_t *written) {
    if (!written || !transform || !(flags&0x1000) || count>UINT32_MAX || (count && !pairs)) return -1;
    size_t selected=count;
    if (flags&0x2000) {
        selected=0;for (size_t i=0;i<count;++i) selected+=pairs[i].flag!=0;
        if (selected!=inliers) return -1;
    }
    size_t stride=4+((flags&0x4000)?2u:0u)+((flags&0x8000)?1u:0u);
    if (selected>(SIZE_MAX-17)/stride) return -1;
    *written=17+selected*stride;
    if (!output) return 0;
    if (capacity<*written) return -1;
    uint32_t header[2]={(uint32_t)selected,inliers};
    for (size_t i=0;i<2;++i) for (unsigned j=0;j<4;++j) output[4*i+j]=(uint8_t)(header[i]>>(8*j));
    output[8]=success;
    for (size_t i=0;i<4;++i) {uint16_t value=(uint16_t)transform[i];output[9+2*i]=(uint8_t)value;output[10+2*i]=(uint8_t)(value>>8);}
    size_t offset=17;
    for (size_t i=0;i<count;++i) if (!(flags&0x2000) || pairs[i].flag) {
        uint16_t values[3]={pairs[i].first,pairs[i].second,pairs[i].distance};
        size_t words=(flags&0x4000)?3:2;
        for (size_t j=0;j<words;++j) {output[offset++]=(uint8_t)values[j];output[offset++]=(uint8_t)(values[j]>>8);}
        if (flags&0x8000) output[offset++]=pairs[i].flag;
    }
    return 0;
}

int fpc_compact_candidates(fpc_candidate **owned_pairs, size_t *count,
                            size_t final_inliers, int filter) {
    if (!owned_pairs || !count || (*count && !*owned_pairs) ||
        *count>SIZE_MAX/sizeof(fpc_candidate)) return -1;
    size_t retained=*count;
    if (filter) {
        retained=0;
        for (size_t i=0;i<*count;++i) retained+=(*owned_pairs)[i].flag!=0;
        if (retained!=final_inliers) return -1;
    }
    fpc_candidate *replacement=NULL;
    if (retained) {
        replacement=malloc(retained*sizeof(*replacement));
        if (!replacement) return 2;
        size_t j=0;
        for (size_t i=0;i<*count;++i)
            if (!filter || (*owned_pairs)[i].flag) replacement[j++]=(*owned_pairs)[i];
    }
    free(*owned_pairs);*owned_pairs=replacement;*count=retained;
    return 0;
}

int fpc_enrollment_check_movement(size_t count, float area, float latest_motion,
                                  float threshold, uint32_t *insufficient_count,
                                  int32_t *report_flag) {
    if (!insufficient_count || !report_flag || count>80) return -1;
    if (count<2) return 0;
    float normalized=latest_motion/fpc_sqrt_recovered(area);
    /* COMISS/JB also takes the clear branch for unordered operands. */
    if (!(threshold>=normalized)) *report_flag=0;
    else { *report_flag=1; ++*insufficient_count; }
    return 0;
}

float fpc_sqrt_recovered(float input) {
    uint32_t bits;
    memcpy(&bits,&input,sizeof(bits));
    uint32_t adjusted=bits+0x800000u;
    uint32_t seed=((190u-(adjusted>>24))*256u+sqrt_seed[(adjusted>>16)&255u])<<15;
    float initial;
    memcpy(&initial,&seed,sizeof(initial));
    float next=initial*((3.0f-((initial*input)*initial))*0.5f);
    return (((3.0f-((next*input)*next))*0.5f)*next)*input;
}

/* 180046200, mode 5. All polynomial arithmetic wraps at 32 bits. */
uint8_t fpc_hessian_angle(int16_t sine, int16_t cosine) {
    int32_t x=cosine,y=sine,base=4096;
    if (!x && !y) return 0;
    if (x==-32768) x=-32767;
    if (y==-32768) y=-32767;
    if (y<=0) {x=-x; y=-y; base=-28672;}
    if (x<0) {int32_t t=y; y=-x; x=t; base+=16384;}
    int32_t a=30274,b=-12540;
    if (x<y) {base+=8192; a=12540; b=-30274;}
    uint32_t den=(uint32_t)(x*a-y*b),num=(uint32_t)(x*b+y*a);
    unsigned leading=32;
    if (den) {leading=0; for(uint32_t bit=0x80000000u;!(den&bit);bit>>=1) ++leading;}
    /* Original de Bruijn lookup returns leading-zero count. */
    unsigned shift=(leading-2)&31;
    int32_t divisor=(int32_t)shift_floor(signed_u32((den<<shift)+0x4000u),15);
    int32_t t=divisor ? (int32_t)(signed_u32(num<<shift)/divisor) : 0;
    int32_t q=(int32_t)shift_floor(signed_u32((uint32_t)t*(uint32_t)t+0x4000u),15);
    int32_t c=(int32_t)shift_floor(signed_u32((uint32_t)t*(uint32_t)q+0x4000u),15);
    int32_t f=(int32_t)shift_floor(signed_u32((uint32_t)c*(uint32_t)q+0x4000u),15);
    int32_t s=(int32_t)shift_floor(signed_u32((uint32_t)f*(uint32_t)q+0x4000u),15);
    uint32_t poly=(uint32_t)base*23040u+(uint32_t)t*7332u-(uint32_t)c*2389u+
                  (uint32_t)f*1141u-(uint32_t)s*325u;
    int16_t angle=signed_u16((uint16_t)shift_floor(shift_floor(signed_u32(poly),1)+16384,15));
    int32_t twice=2*(int32_t)angle;
    if(twice<0) twice+=46080;
    return (uint8_t)shift_floor(twice+128,8);
}

/* 18006c6a0, 15-tap variant. */
static int derivative_kernels(float sigma, int16_t *gaussian,
                               int16_t *first, int16_t *second, unsigned taps) {
    if (!gaussian || !first || !second || !(sigma>=1.0f && sigma<=10.0f)) return -1;
    float g[15], d[15], dd[15], total=0.0f;
    float factor=-0.5f/(sigma*sigma);
    for (unsigned i=0; i<taps; ++i) {
        float x=(float)i-(float)(taps-1)*0.5f;
        g[i]=recovered_exp((x*factor)*x);
        total+=g[i];
        float multiplier=(x+x)*factor;
        d[i]=multiplier*g[i];
        dd[i]=d[i]*multiplier+(factor+factor)*g[i];
    }
    for (unsigned i=0; i<taps; ++i) {
        float a=(g[i]*32768.0f)/total;
        float b=(d[i]*32768.0f)/total;
        float c=(dd[i]*32768.0f)/total;
        gaussian[i]=signed_u16((uint16_t)(int32_t)(a>=0.0f ? a+0.5f : a-0.5f));
        first[i]=signed_u16((uint16_t)(int32_t)(b>=0.0f ? b+0.5f : b-0.5f));
        second[i]=signed_u16((uint16_t)(int32_t)(c>=0.0f ? c+0.5f : c-0.5f));
    }
    return 0;
}

int fpc_gaussian_derivative_kernels(float sigma, int16_t gaussian[15],
                                    int16_t first[15], int16_t second[15]) {
    return derivative_kernels(sigma,gaussian,first,second,15);
}

static size_t reflect_index(int64_t position, size_t length) {
    if (position<0) return (size_t)-position;
    if ((uint64_t)position>=length) return (size_t)(2*(int64_t)length-2-position);
    return (size_t)position;
}

/* 18006d190 horizontal, 18006bb40 vertical. Reflect without repeating endpoint. */
static void convolve_taps(const int16_t *source, int16_t *output, size_t width,
                        size_t height, const int16_t *kernel, int vertical, unsigned taps) {
    for (size_t y=0; y<height; ++y)
        for (size_t x=0; x<width; ++x) {
            uint32_t sum=0;
            for (unsigned tap=0; tap<taps; ++tap) {
                size_t sx=x, sy=y;
                if (vertical) sy=reflect_index((int64_t)y+tap-(int)(taps/2),height);
                else sx=reflect_index((int64_t)x+tap-(int)(taps/2),width);
                int32_t product=(int32_t)source[sy*width+sx]*kernel[tap];
                sum+=(uint32_t)product;
            }
            sum+=0x4000u;
            output[y*width+x]=signed_u16((uint16_t)shift_floor(signed_u32(sum),15));
        }
}

int fpc_hessian_planes(const uint8_t *image, size_t width, size_t height,
                        size_t stride, float sigma, int16_t *xx,
                        int16_t *yy, int16_t *xy) {
    if (!image || !xx || !yy || !xy || width<15 || height<15 || width>256 ||
        height>256 || stride<width || height>SIZE_MAX/stride) return -1;
    int16_t g[15], d[15], dd[15];
    if (fpc_gaussian_derivative_kernels(sigma,g,d,dd)) return -1;
    size_t count=width*height;
    int16_t *buffers=malloc(count*2*sizeof(int16_t));
    if (!buffers) return -1;
    int16_t *source=buffers, *temporary=buffers+count;
    for (size_t y=0; y<height; ++y)
        for (size_t x=0; x<width; ++x) source[y*width+x]=(int16_t)(image[y*stride+x]*64);
    convolve_taps(source,temporary,width,height,dd,0,15);
    convolve_taps(temporary,xx,width,height,g,1,15);
    convolve_taps(source,temporary,width,height,g,0,15);
    convolve_taps(temporary,yy,width,height,dd,1,15);
    convolve_taps(source,temporary,width,height,d,0,15);
    convolve_taps(temporary,xy,width,height,d,1,15);
    free(buffers);
    return 0;
}

int fpc_blur_image7(const uint8_t *source, size_t width, size_t height,
                    size_t stride, float sigma, uint8_t *output,
                    size_t output_stride) {
    if(!source || !output || width<8 || height<8 || width>256 || height>256 ||
       (width&1) || (height&1) || stride<width || output_stride<width ||
       height>SIZE_MAX/stride || height>SIZE_MAX/output_stride) return -1;
    int16_t g[15],d[15],dd[15];
    if(derivative_kernels(sigma,g,d,dd,7)) return -1;
    size_t n=width*height;
    int16_t *buffers=malloc(3*n*sizeof(int16_t));
    if(!buffers) return -1;
    int16_t *input=buffers,*temp=buffers+n,*filtered=buffers+2*n;
    for(size_t y=0;y<height;++y) for(size_t x=0;x<width;++x)
        input[y*width+x]=(int16_t)(source[y*stride+x]*64);
    convolve_taps(input,temp,width,height,g,0,7);
    convolve_taps(temp,filtered,width,height,g,1,7);
    for(size_t y=0;y<height;++y) for(size_t x=0;x<width;++x)
        output[y*output_stride+x]=(uint8_t)shift_floor(filtered[y*width+x]+32,6);
    free(buffers);
    return 0;
}

static int32_t truncate_sse(float value) {
    if (!(value>=-2147483648.0f && value<2147483648.0f)) return INT32_MIN;
    return (int32_t)value;
}

int fpc_hessian_orientation(const uint8_t *image, size_t width, size_t height,
                             size_t stride, float sigma, float regularizer,
                             uint8_t *angles, uint8_t *confidence) {
    if (!image || !angles || !confidence || width<16 || height<16 ||
        width>256 || height>256 || (width&1) || (height&1) || stride<width ||
        height>SIZE_MAX/stride || !(regularizer>=0.0f && regularizer<=3.402823466e38f)) return -1;
    int16_t g[15],d[15],dd[15];
    if(derivative_kernels(sigma,g,d,dd,7)) return -1;
    size_t n=width*height;
    int16_t *buffer=malloc(n*5*sizeof(int16_t));
    if(!buffer) return -1;
    int16_t *source=buffer,*temp=buffer+n,*xx=buffer+2*n,*yy=buffer+3*n,*xy=buffer+4*n;
    for(size_t y=0;y<height;++y) for(size_t x=0;x<width;++x)
        source[y*width+x]=(int16_t)(image[y*stride+x]*64);
    convolve_taps(source,temp,width,height,dd,0,7);
    convolve_taps(temp,xx,width,height,g,1,7);
    convolve_taps(source,temp,width,height,g,0,7);
    convolve_taps(temp,yy,width,height,dd,1,7);
    convolve_taps(source,temp,width,height,d,0,7);
    convolve_taps(temp,xy,width,height,d,1,7);
    for(size_t i=0;i<n;++i) {
        float a=xx[i],b=yy[i],z=xy[i];
        float lp,lm,pu,pv,mu,mv;
        if(z*z>=1.0e-12f) {
            float mean=(a+b)*0.5f;
            float root=fpc_sqrt_recovered(mean*mean-(a*b-z*z));
            lp=mean+root; lm=mean-root;
            pu=z; pv=lp-a; mu=z; mv=lm-a;
        } else {lp=a; lm=b; pu=1.0f; pv=0.0f; mu=0.0f; mv=1.0f;}
        float ap=lp<0.0f ? -lp : lp,am=lm<0.0f ? -lm : lm;
        float weight=((ap-am)*(ap-am)/((am*am+ap*ap)+regularizer))*255.0f;
        float u=am<=ap ? mu : pu,v=am<=ap ? mv : pv;
        float norm=v*v+u*u;
        float cross=(v*u)/norm;
        xx[i]=signed_u16((uint16_t)truncate_sse(((u*u-v*v)/norm)*weight));
        yy[i]=signed_u16((uint16_t)truncate_sse((cross+cross)*weight));
    }
    /* Gaussian-only 15-tap generator uses the same G normalization. */
    derivative_kernels(3.0f,g,d,dd,15);
    convolve_taps(xx,temp,width,height,g,0,15);
    convolve_taps(temp,xx,width,height,g,1,15);
    convolve_taps(yy,temp,width,height,g,0,15);
    convolve_taps(temp,yy,width,height,g,1,15);
    for(size_t i=0;i<n;++i) {
        int32_t c=xx[i],s=yy[i];
        float magnitude=(float)signed_u32((uint32_t)(c*c)+(uint32_t)(s*s));
        confidence[i]=(uint8_t)truncate_sse(fpc_sqrt_recovered(magnitude)*0.4f);
        angles[i]=fpc_hessian_angle((int16_t)s,(int16_t)c);
    }
    free(buffer);
    return 0;
}

int fpc_expand_mask(const uint32_t *words, size_t word_count, size_t bit_stride,
                     size_t origin_x, size_t origin_y, size_t width, size_t height,
                     uint8_t *output, size_t output_stride) {
    if(!words || !output || !width || !height || bit_stride%32 ||
       origin_x>bit_stride || width>bit_stride-origin_x || output_stride<width ||
       height>SIZE_MAX/output_stride || origin_y>SIZE_MAX-height ||
       !bit_stride || origin_y+height>SIZE_MAX/bit_stride ||
       (origin_y+height)*bit_stride/32>word_count) return -1;
    for(size_t y=0;y<height;++y) for(size_t x=0;x<width;++x) {
        size_t bit=(origin_y+y)*bit_stride+origin_x+x;
        output[y*output_stride+x]=(words[bit/32]>>(bit%32)&1u) ? 255 : 0;
    }
    return 0;
}

int fpc_threshold_resized_mask(uint8_t *mask, size_t width, size_t height,
                                size_t stride) {
    if(!mask || !width || !height || stride<width || height>SIZE_MAX/stride) return -1;
    for(size_t y=0;y<height;++y) for(size_t x=0;x<width;++x)
        if(mask[y*stride+x]!=255) mask[y*stride+x]=0;
    return 0;
}

int fpc_pad_image_edges(const uint8_t *source, size_t width, size_t height,
                         size_t stride, size_t padding, uint8_t *output,
                         size_t output_stride) {
    if(!source || !output || !width || !height || width>256 || height>256 ||
       padding>128 || stride<width || output_stride<width+2*padding ||
       height>SIZE_MAX/stride || height+2*padding>SIZE_MAX/output_stride) return -1;
    size_t ow=width+2*padding,oh=height+2*padding;
    for(size_t y=0;y<oh;++y) {
        size_t sy=y<padding ? 0 : y-padding<height ? y-padding : height-1;
        for(size_t x=0;x<ow;++x) {
            size_t sx=x<padding ? 0 : x-padding<width ? x-padding : width-1;
            output[y*output_stride+x]=source[sy*stride+sx];
        }
    }
    return 0;
}

static void sort_feature_scores(fpc_ranked_score *records, ptrdiff_t count) {
    while(count>=2) {
        ptrdiff_t left=0,right=count-1;
        float pivot=records[count/2].score;
        while(left<=right) {
            if(records[left].score<=pivot) {
                if(pivot<=records[right].score) {
                    fpc_ranked_score t=records[left]; records[left]=records[right];
                    records[right]=t; ++left;
                }
                --right;
            } else ++left;
        }
        sort_feature_scores(records,right+1);
        records+=left; count-=left;
    }
}

int fpc_sort_feature_scores(fpc_ranked_score *records, size_t count) {
    if(!records || count>2048) return -1;
    /* Original comparison loop has no progress guarantee for a NaN pivot. */
    for(size_t i=0;i<count;++i) if(records[i].score!=records[i].score) return -1;
    sort_feature_scores(records,(ptrdiff_t)count);
    return 0;
}

int fpc_resize_down(const uint8_t *source, size_t width, size_t height,
                    size_t stride, uint8_t *output, size_t ow,
                    size_t oh, size_t output_stride) {
    if(!source || !output || width>256 || height>256 || !ow || !oh ||
       ow>=width || oh>=height || stride<width || output_stride<ow ||
       height>SIZE_MAX/stride || oh>SIZE_MAX/output_stride) return -1;
    int32_t *temporary=malloc(width*oh*sizeof(int32_t));
    if(!temporary) return -1;
    int32_t xs=(int32_t)((ow/2+(width<<15))/ow);
    int32_t ys=(int32_t)((oh/2+(height<<15))/oh);
    int32_t yp=(ys-32768)/2;
    for(size_t y=0;y<oh;++y,yp+=ys) {
        size_t row=(size_t)(yp>>15);
        int32_t fraction=yp&32767;
        for(size_t x=0;x<width;++x)
            temporary[x*oh+y]=((32768-fraction)*source[row*stride+x]+
                              fraction*source[(row+1)*stride+x]+64)>>7;
    }
    int32_t xp=(xs-32768)/2;
    for(size_t x=0;x<ow;++x,xp+=xs) {
        size_t column=(size_t)(xp>>15);
        uint32_t fraction=(uint32_t)xp&32767u;
        for(size_t y=0;y<oh;++y) {
            uint32_t value=(32768u-fraction)*(uint32_t)temporary[column*oh+y]+
                           fraction*(uint32_t)temporary[(column+1)*oh+y]+0x400000u;
            output[y*output_stride+x]=(uint8_t)shift_floor(signed_u32(value),23);
        }
    }
    free(temporary);
    return 0;
}

int fpc_select_spatial_features(const fpc_ranked_location *ranked, size_t count,
                                size_t wanted, int16_t xmin, int16_t ymin,
                                int16_t xmax, int16_t ymax, int32_t *indices) {
    if(!ranked || !indices || !count || count>2048 || wanted>count ||
       xmax<xmin || ymax<ymin) return -1;
    int32_t *next=malloc(count*sizeof(int32_t));
    if(!next) return -1;
    int32_t heads[9],cells[9];
    for(unsigned i=0;i<9;++i) {heads[i]=-1; cells[i]=(int32_t)i;}
    for(size_t j=count;j>0;--j) {
        size_t i=j-1;
        int32_t x=(int32_t)(((float)((int)ranked[i].x-xmin)*3.0f)/(float)((int)xmax-xmin+1));
        int32_t y=(int32_t)(((float)((int)ranked[i].y-ymin)*3.0f)/(float)((int)ymax-ymin+1));
        if(x<0) x=0;
        if(x>2) x=2;
        if(y<0) y=0;
        if(y>2) y=2;
        unsigned cell=(unsigned)(x+3*y);
        next[i]=heads[cell]; heads[cell]=(int32_t)i;
    }
    uint64_t state=UINT64_C(0xffffffff);
    for(unsigned i=0;i<90;++i) {
        state=UINT64_C(4164903690)*(uint32_t)state+(state>>32);
        unsigned a=(uint32_t)state%9;
        state=UINT64_C(4164903690)*(uint32_t)state+(state>>32);
        unsigned b=(uint32_t)state%9;
        int32_t t=cells[a]; cells[a]=cells[b]; cells[b]=t;
    }
    size_t selected=0; unsigned cursor=0;
    while(selected<wanted) {
        unsigned cell=(unsigned)cells[cursor]; cursor=(cursor+1)%9;
        int32_t at=heads[cell];
        if(at>=0) {indices[selected++]=ranked[at].index; heads[cell]=next[at];}
    }
    free(next);
    return 0;
}

int fpc_limit_feature_budget(const fpc_keypoint *points, size_t count,
                              const fpc_feature_level *levels, size_t level_count,
                              size_t image_width, size_t image_height, int budget,
                              fpc_keypoint *output, size_t capacity,
                              size_t *output_count, size_t selected_per_level[2]) {
    if(!points || !levels || !output || !output_count || !selected_per_level ||
       !level_count || level_count>2 || count>2048 || !image_width || !image_height ||
       image_width>256 || image_height>256 || capacity<count ||
       levels[0].count>count || (level_count==1 ? levels[0].count!=count :
       levels[1].count!=count-levels[0].count)) return -1;
    size_t quotas[2]={count,0};
    if(budget>=0 && count>(size_t)budget) {
        quotas[1]=level_count==2 ? (size_t)budget*50/100 : 0;
        quotas[0]=(size_t)budget-quotas[1];
    } else {
        quotas[0]=levels[0].count;
        if(level_count==2) quotas[1]=levels[1].count;
    }
    size_t offset=0,written=0;
    selected_per_level[0]=selected_per_level[1]=0;
    for(size_t level=0;level<level_count;++level) {
        size_t n=levels[level].count,q=quotas[level];
        if(q>n) q=n;
        selected_per_level[level]=q;
        if(q==n) {
            memmove(output+written,points+offset,n*sizeof(*points)); written+=n;
        } else if(q) {
            fpc_ranked_score ranks[2048]; fpc_ranked_location locations[2048]; int32_t chosen[2048];
            for(size_t i=0;i<n;++i) {ranks[i].index=(int32_t)i; ranks[i].score=points[offset+i].score;}
            if(fpc_sort_feature_scores(ranks,n)) return -1;
            float sx=(float)levels[level].scale_x_q14*0.00006103515625f;
            float sy=(float)levels[level].scale_y_q14*0.00006103515625f;
            float ox=(float)levels[level].offset_x_q4*0.0625f;
            float oy=(float)levels[level].offset_y_q4*0.0625f;
            for(size_t i=0;i<n;++i) {
                const fpc_keypoint *p=points+offset+(size_t)ranks[i].index;
                locations[i].index=ranks[i].index;
                locations[i].x=signed_u16((uint16_t)truncate_sse((float)p->x*sx+ox));
                locations[i].y=signed_u16((uint16_t)truncate_sse((float)p->y*sy+oy));
            }
            if(fpc_select_spatial_features(locations,n,q,0,0,(int16_t)(image_width-1),
                                           (int16_t)(image_height-1),chosen)) return -1;
            for(size_t i=0;i<q;++i) output[written++]=points[offset+(size_t)chosen[i]];
        }
        offset+=n;
    }
    *output_count=written;
    return 0;
}

int fpc_extract_profile300_prepared(const uint8_t *image, size_t stride,
                                    const uint8_t *mask, size_t mask_stride,
                                    const int16_t *weights, size_t weight_count,
                                    fpc_feature *output, size_t capacity,
                                    size_t *count) {
    enum {W=112,H=88,N=W*H,PAD=14,PW=W+2*PAD,PH=H+2*PAD};
    if(!image || !mask || !weights || !output || !count || stride<W || mask_stride<W ||
       stride>SIZE_MAX/H || mask_stride>SIZE_MAX/H || weight_count!=16384 || capacity<300) return -1;
    *count=0;
    int16_t *planes=malloc(3*N*sizeof(int16_t)); float *scores=malloc(N*sizeof(float));
    uint8_t *padded=malloc(PW*PH);
    if(!planes || !scores || !padded) {free(planes);free(scores);free(padded);return -1;}
    fpc_keypoint detected[2048],selected[2048]; size_t found=0,kept=0,per_level[2];
    uint8_t field[27*21];
    int status=fpc_hessian_planes(image,W,H,stride,1.6f,planes,planes+N,planes+2*N);
    if(!status) status=fpc_harris_scores(planes,planes+N,planes+2*N,N,0.04f,scores);
    if(!status) status=fpc_select_float_maxima(scores,W,H,W,mask,mask_stride,4,detected,2048,&found);
    fpc_feature_level level={found,16384,16384,8,8};
    if(!status) status=fpc_limit_feature_budget(detected,found,&level,1,W,H,300,selected,2048,&kept,per_level);
    if(!status && kept) status=fpc_build_orientation_field(image,W,H,stride,field,sizeof(field));
    if(!status && kept) status=fpc_pad_image_edges(image,W,H,stride,PAD,padded,PW);
    for(size_t i=0;!status && i<kept;++i) {
        int8_t angle=0; uint8_t patch[256];
        status=fpc_interpolate_orientation(field,27,21,8+16*selected[i].x,8+16*selected[i].y,&angle);
        float degrees=(float)(shift_floor(360*(int32_t)angle,9)+180);
        if(!status) status=sample_descriptor_roi(padded,PW,PH,PW,patch,16,25,
                            selected[i].x,selected[i].y,degrees,PAD,PAD);
        if(!status) status=fpc_project_descriptor(patch,256,weights,weight_count,output[i].descriptor,16);
        if(!status) {output[i].point=selected[i];output[i].degrees=degrees;}
    }
    if(!status) *count=kept;
    free(planes);free(scores);free(padded);
    return status;
}

/* 1800454f0: orientation-byte to double-angle vector, polynomial fixed math. */
void fpc_angle_vector(uint8_t angle, int32_t *cos_double, int32_t *sin_double) {
    int64_t sign=angle<128 ? 0x5a82 : -0x5a82;
    int64_t a=shift_floor((angle&127)*INT64_C(0x6488)-0x1921e0,6);
    int64_t b=shift_floor(a+1,1);
    int64_t c=shift_floor(shift_floor(b*a+0x4000,15)+1,1);
    int64_t d=shift_floor(shift_floor(c*a+0x4000,15)*0x2aab+0x4000,15);
    int64_t e=shift_floor(shift_floor(d*a+0x4000,15)+2,2);
    int64_t u=0x4000-c+e;
    int64_t v=b-d+shift_floor(shift_floor(e*a+0x4000,15)*0x199a+0x4000,15);
    int64_t x=shift_floor(u*0x5a82-v*sign+0x4000,15);
    int64_t y=shift_floor(u*sign+v*0x5a82+0x4000,15);
    if (cos_double) *cos_double=(int32_t)shift_floor(x*x-y*y+0x2000,14);
    if (sin_double) *sin_double=(int32_t)shift_floor(x*y+0x1000,13);
}

/* 180045600; exact normalization and atan polynomial, 32-bit angle result. */
int32_t fpc_angle_fixed(int32_t first, int32_t second) {
    if ((!first && !second) || first<-32768 || first>32767 || second<-32768 || second>32767) return 0;
    int32_t base=0x1000;
    if (first<1) { second=-second; base=-0x7000; first=-first; }
    int32_t large=first;
    if (second<0) { base+=0x4000; large=-second; second=first; }
    int32_t a,b;
    if (second<large) { base+=0x2000; a=0x30fc; b=-0x7642; }
    else { a=0x7642; b=-0x30fc; }
    uint32_t denominator=(uint32_t)((int64_t)a*second-(int64_t)b*large);
    if (!denominator) return 0;
    unsigned leading=0;
    for (uint32_t mask=0x80000000u; !(denominator&mask); mask>>=1) ++leading;
    unsigned shift=(leading-1)&31;
    uint32_t numerator=(uint32_t)((int64_t)a*large+(int64_t)b*second)<<shift;
    int64_t divisor=shift_floor(signed_u32(denominator<<shift),15);
    if (!divisor) return 0;
    int64_t ratio=signed_u32(numerator)/divisor;
    int64_t square=shift_floor(ratio*ratio+0x4000,15);
    int64_t cube=shift_floor(square*ratio+0x4000,15);
    int64_t fifth=shift_floor(cube*square+0x4000,15);
    int64_t seventh=shift_floor(fifth*square+0x4000,15);
    uint32_t result=(uint32_t)(fifth*0x657-seventh*0x1ce + ratio*0x28bc+
                                (int64_t)base*0x8000-cube*0xd46);
    return (int32_t)signed_u32(result);
}

/* 180061060: clamped field neighbors; Q4 source coordinates and four-pixel cells. */
int fpc_interpolate_orientation(const uint8_t *field, size_t width, size_t height,
                                 int32_t x_q4, int32_t y_q4, int8_t *angle) {
    if (!field || !angle || !width || !height || width>256 || height>256 ||
        x_q4<-4096 || x_q4>4096 || y_q4<-4096 || y_q4>4096) return -1;
    int64_t qx=(int64_t)x_q4-64, qy=(int64_t)y_q4-64;
    int64_t ix=shift_floor(qx,6), iy=shift_floor(qy,6);
    uint32_t fx=(uint32_t)qx&63, fy=(uint32_t)qy&63;
    int64_t cos_sum=0,sin_sum=0;
    for (unsigned dy=0; dy<2; ++dy)
        for (unsigned dx=0; dx<2; ++dx) {
            int64_t nx=ix+dx,ny=iy+dy;
            if (nx<0) nx=0;
            if (ny<0) ny=0;
            if ((uint64_t)nx>=width) nx=(int64_t)width-1;
            if ((uint64_t)ny>=height) ny=(int64_t)height-1;
            int32_t c,s;
            fpc_angle_vector(field[(size_t)ny*width+(size_t)nx],&c,&s);
            unsigned weight=(dx ? fx : 64-fx)*(dy ? fy : 64-fy);
            cos_sum+=(int64_t)c*weight; sin_sum+=(int64_t)s*weight;
        }
    int32_t code=fpc_angle_fixed((int32_t)shift_floor(sin_sum+0x8000,12),
                                  (int32_t)shift_floor(cos_sum+0x8000,12));
    int64_t value=shift_floor((int64_t)code+0x400000,23);
    *angle=(int8_t)(value<=127 ? value : value-256);
    return 0;
}

static void smooth_orientation(const int16_t *input, int16_t *output, size_t width,
                                 size_t height, const int16_t kernel[7], int vertical) {
    for (size_t y=0; y<height; ++y)
        for (size_t x=0; x<width; ++x) {
            uint32_t sum=0;
            for (unsigned k=0; k<7; ++k) {
                int64_t nx=(int64_t)x, ny=(int64_t)y;
                if (vertical) ny+=(int)k-3; else nx+=(int)k-3;
                if (nx<0) nx=0;
                if (ny<0) ny=0;
                if ((uint64_t)nx>=width) nx=(int64_t)width-1;
                if ((uint64_t)ny>=height) ny=(int64_t)height-1;
                sum+=(uint32_t)((int32_t)input[(size_t)ny*width+(size_t)nx]*kernel[k]);
            }
            output[y*width+x]=signed_u16((uint16_t)shift_floor(signed_u32(sum),15));
        }
}

/* 180060200 -> seven-tap clamp smoothing -> 180045600 angle encoding. */
int fpc_build_orientation_field(const uint8_t *image, size_t width, size_t height,
                                 size_t stride, uint8_t *field, size_t field_size) {
    if (!image || !field || width<24 || height<24 || width>256 || height>256 ||
        stride<width || height>SIZE_MAX/stride) return -1;
    size_t fw=(width-4)/4, fh=(height-4)/4, count=fw*fh;
    if (field_size<count) return -1;
    int16_t *buffers=malloc(count*3*sizeof(int16_t));
    if (!buffers) return -1;
    int16_t *cosine=buffers,*sine=buffers+count,*temporary=buffers+count*2;
    for (size_t cy=0;cy<fh;++cy)
        for (size_t cx=0;cx<fw;++cx) {
            int32_t a=0,b=0;
            for (size_t dy=0;dy<4;++dy)
                for (size_t dx=0;dx<4;++dx) {
                    const uint8_t *p=image+(2+cy*4+dy)*stride+2+cx*4+dx;
                    int32_t gx=p[0]+p[stride]-p[1]-p[stride+1];
                    int32_t gy=p[0]+p[1]-p[stride]-p[stride+1];
                    a+=gx*gx-gy*gy; b+=2*gx*gy;
                }
            uint32_t magnitude=((uint32_t)shift_floor(a,1)^(uint32_t)a)|
                                 ((uint32_t)shift_floor(b,1)^(uint32_t)b)|0x2000u;
            unsigned leading=0;
            for (uint32_t bit=0x80000000u; !(magnitude&bit); bit>>=1) ++leading;
            unsigned shift=(18-leading)&31;
            cosine[cy*fw+cx]=signed_u16((uint16_t)shift_floor(a,shift));
            sine[cy*fw+cx]=signed_u16((uint16_t)shift_floor(b,shift));
        }
    float weights[7],total=0.0f;
    int16_t kernel[7];
    float sigma=0x1.333334p+0f;
    float factor=-0.5f/(sigma*sigma);
    for (unsigned k=0;k<7;++k) {
        float x=(float)k-3.0f;
        weights[k]=recovered_exp((x*factor)*x); total+=weights[k];
    }
    for (unsigned k=0;k<7;++k) {
        float value=(weights[k]*32768.0f)/total;
        kernel[k]=(int16_t)(value+0.5f);
    }
    smooth_orientation(cosine,temporary,fw,fh,kernel,0);
    smooth_orientation(temporary,cosine,fw,fh,kernel,1);
    smooth_orientation(sine,temporary,fw,fh,kernel,0);
    smooth_orientation(temporary,sine,fw,fh,kernel,1);
    for (size_t i=0;i<count;++i) {
        int32_t angle=fpc_angle_fixed(sine[i],cosine[i]);
        field[i]=(uint8_t)shift_floor((int64_t)angle+0x400000,23);
    }
    free(buffers);
    return 0;
}

/* 180070110. All intermediate operations reproduce x86 modulo-32 arithmetic. */
int fpc_fit_similarity_pair(const fpc_match_coordinates *a,
                            const fpc_match_coordinates *b, int16_t transform[4]) {
    if (!a || !b || !transform) return -1;
    int32_t dx=(int32_t)b->x-a->x,dy=(int32_t)b->y-a->y;
    int32_t ex=(int32_t)b->target_x-a->target_x,ey=(int32_t)b->target_y-a->target_y;
    uint32_t norm=(uint32_t)dx*(uint32_t)dx+(uint32_t)dy*(uint32_t)dy;
    if (!norm) return -1;
    unsigned leading=0;
    for (uint32_t bit=0x80000000u;!(norm&bit);bit>>=1) ++leading;
    unsigned shift=(leading-1)&31;
    int32_t divisor=(int32_t)shift_floor(signed_u32(norm<<shift),14);
    if (!divisor) return -1;
    uint32_t dot=(uint32_t)dx*(uint32_t)ex+(uint32_t)dy*(uint32_t)ey;
    uint32_t cross=(uint32_t)dx*(uint32_t)ey-(uint32_t)dy*(uint32_t)ex;
    uint32_t round=(uint32_t)shift_floor(divisor,1);
    int64_t c=signed_u32((dot<<shift)+round)/divisor;
    int64_t s=signed_u32((cross<<shift)+round)/divisor;
    if (c<INT32_MIN || c>INT32_MAX || s<INT32_MIN || s>INT32_MAX) return -1;
    uint32_t sx=(uint32_t)((int32_t)a->x+b->x),sy=(uint32_t)((int32_t)a->y+b->y);
    uint32_t tx=((uint32_t)((int32_t)a->target_x+b->target_x+1)<<14)-sx*(uint32_t)c+sy*(uint32_t)s;
    uint32_t ty=((uint32_t)((int32_t)a->target_y+b->target_y+1)<<14)-sx*(uint32_t)s-sy*(uint32_t)c;
    transform[0]=signed_u16((uint16_t)c);transform[1]=signed_u16((uint16_t)s);
    transform[2]=signed_u16((uint16_t)shift_floor(signed_u32(tx),15));
    transform[3]=signed_u16((uint16_t)shift_floor(signed_u32(ty),15));
    return 0;
}

/* 180070620 generates 16 pairs and validity bits, updating two-word state. */
int fpc_sample_geometry_pairs(const fpc_match_coordinates *points, size_t count,
                               uint32_t state[2], unsigned tolerance_shift,
                               int32_t indices[32], uint32_t valid[16]) {
    if (!points || !count || count>32767 || !state || !indices || !valid) return -1;
    for (unsigned batch=0;batch<2;++batch) {
        uint32_t a=state[0],b=state[1];
        a|=(((a^(a<<5))&0x1fe0u)<<18);
        b|=(((b^(b<<5))&0x1fe0u)<<18);
        for (unsigned k=1;k<=8;++k) {
            unsigned offset=batch*16+(k-1)*2;
            indices[offset]=(int32_t)((count*(uint16_t)(a>>k))>>16);
            indices[offset+1]=(int32_t)((count*(uint16_t)(b>>k))>>16);
        }
        state[0]=a>>8;state[1]=b>>8;
    }
    for (unsigned i=0;i<16;++i) {
        const fpc_match_coordinates *a=points+indices[i*2],*b=points+indices[i*2+1];
        int32_t dx=(int32_t)b->x-a->x,dy=(int32_t)b->y-a->y;
        int32_t ex=(int32_t)b->target_x-a->target_x,ey=(int32_t)b->target_y-a->target_y;
        int64_t n=signed_u32((uint32_t)dx*(uint32_t)dx+(uint32_t)dy*(uint32_t)dy);
        int64_t m=signed_u32((uint32_t)ex*(uint32_t)ex+(uint32_t)ey*(uint32_t)ey);
        int64_t tolerance=shift_floor(n,tolerance_shift&31);
        int64_t low=signed_u32((uint32_t)n-(uint32_t)tolerance);
        int64_t high=signed_u32((uint32_t)n+(uint32_t)tolerance);
        valid[i]=(uint32_t)(n>256 && low<m && m<high);
    }
    return 0;
}

uint32_t fpc_similarity_error(const fpc_match_coordinates *p, const int16_t t[4]) {
    uint32_t x=(uint32_t)(int32_t)p->x,y=(uint32_t)(int32_t)p->y;
    uint32_t c=(uint32_t)(int32_t)t[0],s=(uint32_t)(int32_t)t[1];
    uint32_t vx=x*c-y*s+((uint32_t)(int32_t)t[2]<<14)-((uint32_t)(int32_t)p->target_x<<14);
    uint32_t vy=y*c+x*s+((uint32_t)(int32_t)t[3]<<14)-((uint32_t)(int32_t)p->target_y<<14);
    uint32_t dx=(uint32_t)shift_floor(signed_u32(vx),14),dy=(uint32_t)shift_floor(signed_u32(vy),14);
    return dx*dx+dy*dy;
}

int fpc_verify_geometry_profile300(const fpc_match_coordinates *points, size_t count,
                                   fpc_candidate *pairs, const uint8_t *source_membership,
                                   size_t source_membership_size, uint8_t *target_membership,
                                   size_t target_membership_size, fpc_geometry_result *result) {
    static const uint16_t limits[16]={0x3334,0x8000,0x5dc0,0x44c0,0x3334,0x2148,0x1917,0x13b7,
                                     0x0eda,0x0c09,0x0979,0x072c,0x0419,0x0290,0x018a,0x0107};
    if (!result || count>32767 || (count && (!points || !pairs)) ||
        (source_membership_size && !source_membership) ||
        (target_membership_size && !target_membership)) return -1;
    for (size_t i=0;i<count;++i)
        if ((size_t)(pairs[i].first>>3)>=source_membership_size ||
            (size_t)(pairs[i].second>>3)>=target_membership_size) return -1;
    /* As in the original early guard, preserve all result fields except success. */
    result->success=0;
    if (count<8) return 0;
    uint32_t state[2]={0xfffe,0x8300},valid[16];int32_t indices[32];
    uint32_t quota[16];
    for (unsigned i=0;i<16;++i) quota[i]=(10000u*limits[i])>>15;
    int16_t best_transform[4]={0};int32_t best=0,limit=1500,accepted=0,progress=0;
    int32_t reciprocal=32768/(int32_t)count;
    for (int32_t iteration=0;iteration<limit;++iteration) {
        unsigned slot=(unsigned)iteration&15;
        if (!slot && fpc_sample_geometry_pairs(points,count,state,3,indices,valid)) return -1;
        if (valid[slot]) {
            int16_t transform[4];accepted+=32768;
            if (fpc_fit_similarity_pair(points+indices[slot*2],points+indices[slot*2+1],transform)) return -1;
            if (iteration>1500 && accepted<progress) limit=iteration;
            else {
                int32_t inliers=0;
                for (size_t i=0;i<count;++i)
                    inliers+=signed_u32(fpc_similarity_error(points+i,transform))<768;
                if (inliers>best) {
                    best=inliers;memcpy(best_transform,transform,sizeof(best_transform));
                    int32_t bucket=(int32_t)shift_floor(inliers*reciprocal,10);
                    if (bucket>15) bucket=15;
                    limit=(int32_t)quota[bucket];
                }
            }
        }
        progress+=4424;
    }
    memcpy(result->transform,best_transform,sizeof(best_transform));
    result->inliers=best;result->spatial_inliers=best;
    if (best>0) {
        for (size_t i=0;i<count;++i)
            pairs[i].flag=(uint8_t)(signed_u32(fpc_similarity_error(points+i,best_transform))<768);
        for (size_t i=0;i<count;++i) if (pairs[i].flag)
            for (size_t j=i+1;j<count;++j) if (pairs[j].flag) {
                int32_t dx=(int32_t)points[i].x-points[j].x,dy=(int32_t)points[i].y-points[j].y;
                if (signed_u32((uint32_t)dx*(uint32_t)dx+(uint32_t)dy*(uint32_t)dy)<3584) {
                    pairs[j].flag=0;--result->inliers;
                }
            }
        result->spatial_inliers=result->inliers;
        result->low_movement=0;
        if (result->inliers) {
            int32_t sx=0,sy=0;
            for (size_t i=0;i<count;++i) if (pairs[i].flag) {
                int32_t dx=(int32_t)points[i].x-points[i].target_x,dy=(int32_t)points[i].y-points[i].target_y;
                sx+=dx<0?-dx:dx;sy+=dy<0?-dy:dy;
            }
            if (sx/result->inliers<32 || sy/result->inliers<32) {
                for (size_t i=0;i<count;++i) pairs[i].flag=0;
                result->inliers=0;result->low_movement=1;
            }
        }
        int32_t member_count=0;
        for (size_t i=0;i<count;++i)
            if (pairs[i].flag==1 && ((source_membership[pairs[i].first>>3]>>(pairs[i].first&7))&1)) ++member_count;
        if (member_count<4) result->inliers=member_count;
        else for (size_t i=0;i<count;++i) if (pairs[i].flag==1) {
            int32_t dx=(int32_t)points[i].x-points[i].target_x,dy=(int32_t)points[i].y-points[i].target_y;
            if (signed_u32((uint32_t)dx*(uint32_t)dx+(uint32_t)dy*(uint32_t)dy)>=768)
                target_membership[pairs[i].second>>3]|=(uint8_t)(1u<<(pairs[i].second&7));
        }
    }
    /* Original success uses the best pre-filter consensus, not final score. */
    result->success=(uint8_t)(best>=8);
    return 0;
}

static int capture_compact_levels_valid(const fpc_capture_payload_view *view) {
    if (!view || !view->levels || !view->level_fields ||
        (view->count && !view->compact_coordinates)) return 0;
    size_t total=0;
    for (size_t l=0;l<view->levels;++l) {
        uint16_t n=view->level_fields[l*5];
        if (n>32767) return 0;
        total+=n;
    }
    return total==view->count;
}

static void capture_compact_point(const fpc_capture_payload_view *view, uint16_t index,
                                   int16_t *x, int16_t *y) {
    size_t level=0,end=view->level_fields[0];
    while (index>=end) end+=view->level_fields[++level*5];
    const uint16_t *fields=view->level_fields+level*5;
    int32_t px=(int16_t)fields[1]*(int32_t)view->compact_coordinates[2*(size_t)index];
    int32_t py=(int16_t)fields[2]*(int32_t)view->compact_coordinates[2*(size_t)index+1];
    /* Floor division reproduces signed SAR without implementation-defined shifts. */
    px=px>=0?px/1024:-((-px+1023)/1024);
    py=py>=0?py/1024:-((-py+1023)/1024);
    *x=(int16_t)(uint16_t)(px+(int16_t)fields[3]);
    *y=(int16_t)(uint16_t)(py+(int16_t)fields[4]);
}

int fpc_capture_candidate_coordinates(const fpc_capture_payload_view *first,
                                       const fpc_capture_payload_view *second,
                                       const fpc_candidate *pairs, size_t count,
                                       fpc_match_coordinates *output) {
    if (!capture_compact_levels_valid(first) || !capture_compact_levels_valid(second) ||
        (count && (!pairs || !output))) return -1;
    for (size_t i=0;i<count;++i)
        if (pairs[i].first>=first->count || pairs[i].second>=second->count) return -1;
    for (size_t i=0;i<count;++i) {
        capture_compact_point(first,pairs[i].first,&output[i].x,&output[i].y);
        capture_compact_point(second,pairs[i].second,&output[i].target_x,&output[i].target_y);
    }
    return 0;
}

int fpc_match_profile300_captures(const fpc_capture_payload_view *first,
                                  const fpc_capture_payload_view *second,
                                  uint8_t *target_membership, size_t target_membership_size,
                                  fpc_candidate *pairs, size_t capacity, size_t *pair_count,
                                  fpc_geometry_result *result) {
    if (!capture_compact_levels_valid(first) || !capture_compact_levels_valid(second) ||
        first->levels!=1 || second->levels!=1 || first->mode!=1 || second->mode!=1 ||
        first->descriptor_bytes!=16 || second->descriptor_bytes!=16 ||
        first->count>32767 || second->count>32767 || !pair_count || !result || capacity<first->count ||
        (first->count && (!pairs || !first->descriptors || !first->membership)) ||
        (second->count && !second->descriptors) || target_membership_size<(second->count+7)/8 ||
        (target_membership_size && !target_membership)) return -1;
    memset(result,0,sizeof(*result));*pair_count=0;
    if (!first->count || !second->count) return 0;
    uint8_t *matrix=malloc((size_t)first->count*second->count);
    fpc_match_coordinates *coordinates=malloc((size_t)first->count*sizeof(*coordinates));
    if (!matrix || !coordinates) {free(matrix);free(coordinates);return -1;}
    for (size_t i=0;i<first->count;++i) for (size_t j=0;j<second->count;++j)
        matrix[i*second->count+j]=(uint8_t)fpc_descriptor_distance128(first->descriptors+i*16,second->descriptors+j*16);
    int status=fpc_mutual_candidates(matrix,first->count,second->count,second->count,64,0,0,pairs,capacity,pair_count);
    if (!status) status=fpc_capture_candidate_coordinates(first,second,pairs,*pair_count,coordinates);
    if (!status) status=fpc_verify_geometry_profile300(coordinates,*pair_count,pairs,first->membership,
                        (first->count+7)/8,target_membership,target_membership_size,result);
    free(matrix);free(coordinates);return status;
}

int fpc_match_profile300_collection(const fpc_loaded_collection *collection,
                                    const fpc_capture_payload_view *query,
                                    uint8_t *query_membership, size_t membership_size,
                                    fpc_collection_match_result *output) {
    if (!collection || !query || !output || collection->count>80 ||
        (collection->count && !collection->captures)) return -1;
    size_t capacity=0;
    for (size_t i=0;i<collection->count;++i) {
        size_t n=collection->captures[i].view.count;
        if (n>32767) return -1;
        if (n>capacity) capacity=n;
    }
    fpc_candidate *pairs=capacity?malloc(capacity*sizeof(*pairs)):NULL;
    if (capacity && !pairs) return -1;
    fpc_collection_match_result result={0};result.count=collection->count;result.selected_capture=-1;
    int16_t previous_transform[4]={0};
    for (size_t i=0;i<collection->count;++i) {
        size_t pair_count=0;fpc_geometry_result geometry={0};
        int status=fpc_match_profile300_captures(&collection->captures[i].view,query,
                    query_membership,membership_size,pairs,capacity,&pair_count,&geometry);
        if (status) {free(pairs);return status;}
        /* Original reuses a match record; an empty candidate set leaves its transform. */
        if (!pair_count) memcpy(geometry.transform,previous_transform,sizeof(previous_transform));
        else memcpy(previous_transform,geometry.transform,sizeof(previous_transform));
        result.scores[i]=(uint16_t)geometry.inliers;result.spatial_scores[i]=(uint16_t)geometry.spatial_inliers;
        memcpy(result.transforms[i],geometry.transform,sizeof(geometry.transform));
        if (result.scores[i]>result.score) {result.score=result.scores[i];result.selected_capture=(int)i;}
    }
    result.rank=(float)result.score;free(pairs);*output=result;return 0;
}

int fpc_identify_profile300(const fpc_loaded_collection *const *collections, size_t count,
                            const fpc_capture_payload_view *query, int query_quality,
                            uint8_t *query_membership, size_t membership_size,
                            const fpc_identification_policy *policy,
                            fpc_identification_result *output) {
    if (!query || !policy || !output || count>100 || (count && !collections) ||
        policy->reported_score_limit<0) return -1;
    fpc_identification_result result={0};result.selected_template=-1;
    for (size_t i=0;i<count;++i) {
        fpc_collection_match_result match={0};
        int status=fpc_match_profile300_collection(collections[i],query,query_membership,membership_size,&match);
        if (status) return status;
        result.tested[i]=1;++result.evaluated;
        if (match.score>result.score) {
            result.score=match.score;result.selected_capture=match.selected_capture;
            if ((int)match.score>=policy->threshold) {
                result.matched=1;result.selected_template=(int)i;break;
            }
        }
    }
    result.reported_score=(uint16_t)((int)result.score<policy->reported_score_limit?
                                    result.score:policy->reported_score_limit);
    result.good_quality=(int)result.score>=policy->good_score_threshold ||
                        query_quality>=policy->good_query_quality_threshold;
    *output=result;return 0;
}

int fpc_match_profile300_features(const fpc_feature *first, size_t first_count,
                                  const fpc_feature *second, size_t second_count,
                                  const uint8_t *source_membership, size_t source_membership_size,
                                  uint8_t *target_membership, size_t target_membership_size,
                                  fpc_candidate *pairs, size_t capacity, size_t *pair_count,
                                  fpc_geometry_result *result) {
    if (!pair_count || !result || first_count>32767 || second_count>32767 ||
        capacity<first_count || (first_count && (!first || !pairs)) ||
        (second_count && !second) || source_membership_size<(first_count+7)/8 ||
        target_membership_size<(second_count+7)/8 ||
        (source_membership_size && !source_membership) ||
        (target_membership_size && !target_membership)) return -1;
    memset(result,0,sizeof(*result));*pair_count=0;
    if (!first_count || !second_count) return 0;
    uint8_t *matrix=malloc(first_count*second_count);
    fpc_match_coordinates *coordinates=malloc(first_count*sizeof(*coordinates));
    if (!matrix || !coordinates) {free(matrix);free(coordinates);return -1;}
    for (size_t i=0;i<first_count;++i) for (size_t j=0;j<second_count;++j)
        matrix[i*second_count+j]=(uint8_t)fpc_descriptor_distance128(first[i].descriptor,second[j].descriptor);
    int status=fpc_mutual_candidates(matrix,first_count,second_count,second_count,64,0,0,pairs,capacity,pair_count);
    if (!status) {
        for (size_t i=0;i<*pair_count;++i) {
            const fpc_keypoint *a=&first[pairs[i].first].point,*b=&second[pairs[i].second].point;
            coordinates[i]=(fpc_match_coordinates){(int16_t)(a->x*16),(int16_t)(a->y*16),(int16_t)(b->x*16),(int16_t)(b->y*16)};
        }
        status=fpc_verify_geometry_profile300(coordinates,*pair_count,pairs,source_membership,
                                             source_membership_size,target_membership,target_membership_size,result);
    }
    free(matrix);free(coordinates);return status;
}

int fpc_enrollment_pair_index(size_t capacity, size_t first, size_t second, size_t *index) {
    if (!index || capacity<2 || capacity>65535 || first>=capacity || second>=capacity || first==second) return -1;
    size_t low=first<second?first:second,high=first<second?second:first;
    *index=low*(capacity-2)-low*(low-1)/2+high-1;
    return 0;
}

int fpc_enrollment_swap_capture_scores(uint16_t *scores, size_t score_count,
                                      size_t capacity, size_t first, size_t second) {
    if (!scores || capacity<2 || capacity>65535 || first>=capacity || second>=capacity ||
        score_count<capacity*(capacity-1)/2) return -1;
    if (first==second) return 0;
    for (size_t i=0;i<capacity;++i) if (i!=first && i!=second) {
        size_t a=0,b=0;
        if (fpc_enrollment_pair_index(capacity,first,i,&a) ||
            fpc_enrollment_pair_index(capacity,second,i,&b)) return -1;
        uint16_t value=scores[a];scores[a]=scores[b];scores[b]=value;
    }
    return 0;
}

int fpc_enrollment_select_capture(const uint16_t *graph, size_t graph_size,
                                  size_t count, size_t capacity,
                                  const uint16_t *new_spatial_scores,
                                  const uint16_t *order, const uint16_t *ages,
                                  size_t protected_count, uint16_t age_threshold,
                                  int32_t *selected) {
    if (!selected || capacity<2 || capacity>65535 || count>capacity) return -1;
    *selected=-1;
    if (count<capacity) {*selected=(int32_t)count;return 0;}
    if (!graph || graph_size<capacity*(capacity-1)/2 || !new_spatial_scores || !order || !ages) return -1;
    for (size_t i=0;i<capacity;++i) if (order[i]>=count) return -1;
    uint32_t *cost=calloc(count+1,sizeof(*cost));
    if (!cost) return -1;
    for (size_t i=0;i<count;++i) {
        uint32_t value=new_spatial_scores[i];cost[i]=value*value;cost[count]+=cost[i];
    }
    for (size_t i=0;i<count;++i) for (size_t j=i+1;j<count;++j) {
        size_t index=0;
        if (fpc_enrollment_pair_index(capacity,i,j,&index)) {free(cost);return -1;}
        uint32_t value=graph[index],square=value*value;
        cost[i]+=square;cost[j]+=square;
    }
    uint32_t best=cost[count];int aged=0;size_t i=protected_count;
    for (;i<capacity;++i) {
        if (aged) break;
        size_t capture=order[i];
        if (best<cost[capture] || ages[capture]>=age_threshold) {
            best=cost[capture];*selected=(int32_t)capture;
            aged=ages[capture]>=age_threshold;
        }
    }
    for (;i<capacity;++i) {
        size_t capture=order[i];
        if (best<cost[capture] && ages[capture]>=age_threshold) {
            best=cost[capture];*selected=(int32_t)capture;
        }
    }
    free(cost);return 0;
}

int fpc_enrollment_write_capture_scores(uint16_t *graph, size_t graph_size,
                                        size_t *count, size_t capacity, size_t capture,
                                        const uint16_t *new_spatial_scores, size_t score_count) {
    if (!graph || !count || capacity<2 || capacity>65535 || *count>capacity ||
        graph_size<capacity*(capacity-1)/2 || capture>*count || capture>=capacity ||
        !new_spatial_scores || score_count<*count) return -1;
    for (size_t i=0;i<*count;++i) if (i!=capture) {
        size_t index=0;if (fpc_enrollment_pair_index(capacity,i,capture,&index)) return -1;
        graph[index]=new_spatial_scores[i];
    }
    if (capture==*count) ++*count;
    return 0;
}

void fpc_loaded_template_destroy(fpc_loaded_template *template_data) {
    if (!template_data) return;
    fpc_retained_graph_destroy(&template_data->graph);
    fpc_loaded_collection_destroy(&template_data->collection);
    memset(template_data,0,sizeof(*template_data));
}

int fpc_loaded_template_retain_capture(fpc_loaded_template *template_data,
                                       const uint16_t *spatial_scores, size_t score_count,
                                       uint16_t protection, fpc_loaded_capture *incoming,
                                       int32_t *selected) {
    if (!template_data || !incoming || !selected) return 1;
    *selected=-1;fpc_retained_graph *graph=&template_data->graph;
    fpc_loaded_collection *collection=&template_data->collection;
    if (graph->used>80 || graph->capacity<2 || graph->used>graph->capacity ||
        collection->count!=graph->used || collection->capacity<graph->capacity ||
        !graph->scores || graph->score_count<(size_t)graph->capacity*(graph->capacity-1)/2 ||
        score_count<graph->used || (graph->used && !spatial_scores) ||
        (graph->used==graph->capacity && (!graph->ages || graph->age_count<graph->used || !graph->order))) return 1;
    uint16_t scores[80]={0};if (graph->used) memcpy(scores,spatial_scores,graph->used*sizeof(*scores));
    graph->protected_count=graph->protected_limit=protection;
    if (fpc_enrollment_select_capture(graph->scores,graph->score_count,graph->used,graph->capacity,
            scores,graph->order,graph->ages,protection,graph->age_threshold,selected)) return 1;
    if (*selected<0) return 0;
    size_t count=graph->used;
    /* Allocate/transfer before graph writes so allocation failure cannot split counts. */
    int status=fpc_loaded_collection_take_capture(collection,incoming,(size_t)*selected);
    if (status) return status;
    status=fpc_enrollment_write_capture_scores(graph->scores,graph->score_count,&count,graph->capacity,
                                              (size_t)*selected,scores,graph->used);
    if (status) return 1; /* Prevalidated above; cannot fail for the selected slot. */
    graph->used=(uint16_t)count;return 0;
}

int fpc_update_template_after_match(fpc_loaded_template *template_data,
                                    fpc_loaded_capture *incoming,
                                    int32_t quality28, int32_t quality32, int32_t quality16,
                                    const uint16_t *spatial_scores, size_t score_count,
                                    const fpc_template_update_policy *policy,
                                    fpc_template_update_state *state, uint8_t *reported_changed) {
    if (!policy || !state || !reported_changed) return 1;
    *reported_changed=0;
    if (state->code!=102) return 1041;
    state->code=103;int status=0;
    if (template_data && state->matched==1 && state->update_allowed==1 && state->age_update_allowed==1) {
        if (fpc_retained_graph_increment_ages(&template_data->graph)) return 1;
        /* Original ignores reset rejection (e.g. selected signed byte -1). */
        (void)fpc_retained_graph_reset_age(&template_data->graph,state->selected_capture);
        if (state->reported_score>=policy->minimum_score && quality28>=policy->minimum_quality28 &&
            quality32>=policy->minimum_quality32 && quality16>=policy->minimum_quality16) {
            int32_t selected=-1;
            status=fpc_loaded_template_retain_capture(template_data,spatial_scores,score_count,policy->protection,incoming,&selected);
            if (!status && selected>=0) (void)fpc_retained_graph_reset_age(&template_data->graph,selected);
            state->retained_slot=selected;
        }
        state->changed=1;
    }
    *reported_changed=state->changed;return status;
}

int fpc_retained_graph_increment_ages(fpc_retained_graph *graph) {
    if (!graph || graph->used>graph->age_count || (graph->used && !graph->ages)) return 1;
    for (size_t i=0;i<graph->used;++i) if (graph->ages[i]!=UINT16_MAX) ++graph->ages[i];
    return 0;
}

int fpc_retained_graph_reset_age(fpc_retained_graph *graph, int index) {
    if (!graph || index<0 || index>graph->used || (size_t)index>=graph->age_count || !graph->ages) return 1;
    graph->ages[index]=0;return 0;
}

int fpc_template_load_default(const uint8_t *data, size_t size,
                                uint8_t retention_capacity, fpc_loaded_template *output) {
    uint32_t version=0;
    if (!output || !retention_capacity || fpc_template_validate(data,size,&version,NULL) || version!=0x001a0000) return 140;
    size_t length=0,offset=8;
    if (checked_block(data+offset,size-offset,UINT32_C(305398016),&length) || length!=16) return 140;
    fpc_loaded_template result={0};
    result.metadata=(uint16_t)(data[offset+8]|(uint16_t)data[offset+9]<<8);
    uint16_t count=(uint16_t)(data[offset+10]|(uint16_t)data[offset+11]<<8);offset+=length;
    if (!count || checked_block(data+offset,size-offset,UINT32_C(305398528),&length)) return 140;
    uint16_t pending=0;int status=fpc_retained_graph_load_payload(data+offset+8,length-12,&result.graph,&pending);
    if (status) return status==2?2:140;
    if (pending || result.graph.used!=count) {fpc_loaded_template_destroy(&result);return 140;}
    offset+=length;size_t consumed=0;
    status=fpc_collection_load_default(data+offset,size-offset,&result.collection,&consumed);
    if (status) {fpc_loaded_template_destroy(&result);return status;}
    offset+=consumed;
    if (result.collection.count!=count || checked_block(data+offset,size-offset,UINT32_C(305398784),&length) ||
        offset+length!=size) {fpc_loaded_template_destroy(&result);return 140;}
    status=fpc_retained_graph_load_ages(&result.graph,data+offset+8,length-12,retention_capacity);
    if (status) {fpc_loaded_template_destroy(&result);return status==2?2:140;}
    *output=result;return 0;
}

int fpc_template_serialize_default(const fpc_retained_graph *graph,
                                     const fpc_capture_payload_view *captures, size_t count,
                                     uint32_t capture_capacity, uint16_t metadata,
                                     uint8_t retention_capacity, uint8_t *output,
                                     size_t capacity, size_t *written) {
    if (!graph || !written || !count || graph->used!=count || !retention_capacity ||
        !graph->ages || graph->age_count<retention_capacity) return -1;
    size_t graph_size=0,collection_size=0;
    if (fpc_retained_graph_payload(graph,0,NULL,0,&graph_size) ||
        fpc_collection_serialize_default(captures,count,capture_capacity,NULL,0,&collection_size)) return -1;
    size_t total=24+12+graph_size+collection_size+12+2u*retention_capacity;
    if (total>INT32_MAX) return -1;
    *written=total;if (!output) return 0;
    if (capacity<total) return -1;
    output[0]=26;output[1]=0;output[2]=0;output[3]=0;store_le32(output+4,(uint32_t)total);
    store_le32(output+8,UINT32_C(305398016));store_le32(output+12,16);
    output[16]=(uint8_t)metadata;output[17]=(uint8_t)(metadata>>8);output[18]=(uint8_t)count;output[19]=(uint8_t)(count>>8);
    store_le32(output+20,fpc_crc32(output+8,12));
    size_t offset=24,size=0;
    store_le32(output+offset,UINT32_C(305398528));store_le32(output+offset+4,(uint32_t)(graph_size+12));
    if (fpc_retained_graph_payload(graph,0,output+offset+8,graph_size,&size)) return -1;
    store_le32(output+offset+8+size,fpc_crc32(output+offset,size+8));offset+=size+12;
    if (fpc_collection_serialize_default(captures,count,capture_capacity,output+offset,collection_size,&size)) return -1;
    offset+=size;store_le32(output+offset,UINT32_C(305398784));store_le32(output+offset+4,12+2u*retention_capacity);
    for (size_t i=0;i<retention_capacity;++i) {output[offset+8+2*i]=(uint8_t)graph->ages[i];output[offset+9+2*i]=(uint8_t)(graph->ages[i]>>8);}
    store_le32(output+offset+8+2u*retention_capacity,fpc_crc32(output+offset,8+2u*retention_capacity));
    return 0;
}

int fpc_retained_graph_load_ages(fpc_retained_graph *graph, const uint8_t *data,
                                  size_t size, uint8_t retention_capacity) {
    if (!graph || !retention_capacity || !data || size!=2u*retention_capacity) return -1;
    uint16_t *ages=malloc(size);if (!ages) return 2;
    for (size_t i=0;i<retention_capacity;++i) ages[i]=(uint16_t)(data[2*i]|(uint16_t)data[2*i+1]<<8);
    free(graph->ages);graph->ages=ages;graph->age_count=retention_capacity;return 0;
}

int fpc_retained_graph_load_payload(const uint8_t *data, size_t size,
                                     fpc_retained_graph *output, uint16_t *pending_count) {
    if (!data || !output || !pending_count || size<12) return -1;
    uint16_t h[6];for (size_t i=0;i<6;++i) h[i]=(uint16_t)(data[2*i]|(uint16_t)data[2*i+1]<<8);
    if (!h[0]) return 1;
    if (h[1]<2 || h[0]>h[1] || h[0]>80 || h[5]>10) return -1;
    size_t edges=(size_t)h[1]*(h[1]-1)/2,needed=12+2*((size_t)h[1]+edges);
    if (size!=needed) return -1;
    fpc_retained_graph result={0};result.used=h[0];result.capacity=h[1];result.protected_count=h[2];
    result.protected_limit=h[3];result.age_threshold=h[4];result.score_count=edges;
    result.order=malloc(2u*h[1]);result.scores=malloc(2*edges);
    if (!result.order || !result.scores) {fpc_retained_graph_destroy(&result);return 2;}
    size_t offset=12;
    for (size_t i=0;i<h[1]+edges;++i) {
        uint16_t value=(uint16_t)(data[offset]|(uint16_t)data[offset+1]<<8);offset+=2;
        if (i<h[1]) result.order[i]=value;else result.scores[i-h[1]]=value;
    }
    *pending_count=h[5];*output=result;return 0;
}

int fpc_retained_graph_payload(const fpc_retained_graph *graph, uint16_t pending_count,
                                uint8_t *output, size_t capacity, size_t *written) {
    if (!graph || !written || graph->capacity<2 || graph->used>graph->capacity ||
        !graph->order || !graph->scores || graph->score_count<(size_t)graph->capacity*(graph->capacity-1)/2) return -1;
    size_t words=6+graph->capacity+(size_t)graph->capacity*(graph->capacity-1)/2;
    *written=words*2;
    if (!output) return 0;
    if (capacity<*written) return -1;
    uint16_t header[6]={graph->used,graph->capacity,graph->protected_count,
        graph->protected_limit,graph->age_threshold,pending_count};
    for (size_t i=0;i<words;++i) {
        uint16_t value=i<6?header[i]:i<6u+graph->capacity?graph->order[i-6]:graph->scores[i-6-graph->capacity];
        output[2*i]=(uint8_t)value;output[2*i+1]=(uint8_t)(value>>8);
    }
    return 0;
}

void fpc_retained_graph_destroy(fpc_retained_graph *graph) {
    if (!graph) return;
    free(graph->scores);free(graph->order);free(graph->ages);
    memset(graph,0,sizeof(*graph));
}

int fpc_retained_graph_create(const uint16_t *pair_scores, size_t pair_count,
                               size_t used, uint8_t retention_capacity,
                               uint16_t protection, fpc_retained_graph *output) {
    if (!output || used>80 || (used>1 && (!pair_scores || pair_count<used*(used-1)/2))) return -1;
    size_t capacity=used>retention_capacity?used:retention_capacity;
    if (capacity<2) return -1;
    fpc_retained_graph result={0};result.used=(uint16_t)used;result.capacity=(uint16_t)capacity;
    result.protected_count=protection;result.protected_limit=protection;
    result.age_threshold=(uint16_t)(3*capacity);result.score_count=capacity*(capacity-1)/2;result.age_count=capacity;
    result.scores=calloc(result.score_count,sizeof(*result.scores));
    result.order=malloc(capacity*sizeof(*result.order));result.ages=malloc(capacity*sizeof(*result.ages));
    if (!result.scores || !result.order || !result.ages) {fpc_retained_graph_destroy(&result);return 2;}
    for (size_t i=0;i<capacity;++i) {result.order[i]=(uint16_t)i;result.ages[i]=(uint16_t)(2u*retention_capacity);}
    for (size_t later=1;later<used;++later) for (size_t earlier=0;earlier<later;++earlier) {
        size_t index=0;fpc_enrollment_pair_index(capacity,earlier,later,&index);
        result.scores[index]=pair_scores[later*(later-1)/2+earlier];
    }
    *output=result;return 0;
}

int fpc_enrollment_initial_order(const uint16_t *scores, size_t score_count,
                                  size_t used, size_t capacity,
                                  uint16_t *order, size_t order_count) {
    if (!order || capacity<2 || capacity>65535 || used>capacity ||
        order_count<capacity || !scores || score_count<capacity*(capacity-1)/2) return -1;
    uint32_t *cost=calloc(capacity,sizeof(*cost));
    if (!cost) return 2;
    for (size_t i=0;i<capacity;++i) order[i]=(uint16_t)i;
    for (size_t i=0;i<used;++i) for (size_t j=i+1;j<used;++j) {
        size_t index=0;fpc_enrollment_pair_index(capacity,i,j,&index);
        uint32_t value=scores[index];value*=value;
        cost[i]+=value;cost[j]+=value;
    }
    for (size_t end=used;end>1;) {
        size_t last=0;
        for (size_t i=1;i<end;++i) if (cost[i-1]>cost[i]) {
            uint32_t c=cost[i];cost[i]=cost[i-1];cost[i-1]=c;
            uint16_t o=order[i];order[i]=order[i-1];order[i-1]=o;last=i;
        }
        end=last;
    }
    free(cost);return 0;
}

int fpc_enrollment_progress_profile300(int32_t count, float area,
                                       float normalized_motion, float relative_area_change,
                                       uint8_t *early_complete_latched,
                                       fpc_enrollment_progress *result) {
    if (!result || !early_complete_latched || count<0 || count>80 ||
        !(area>=0.0f) || !(normalized_motion>=0.0f) || !(relative_area_change>=0.0f)) return -1;
    float progress=((float)count/13.0f)*100.0f;
    if (progress>=100.0f) progress=100.0f;
    result->percent=(int32_t)progress;
    if (count>=3 && normalized_motion>0.4f && relative_area_change<0.085f && area>=25000.0f)
        *early_complete_latched=1;
    if (count>=7 && *early_complete_latched==1) result->percent=100;
    result->complete=(uint8_t)(result->percent>=100);
    result->remaining=result->percent>=100?0:13-count;
    return 0;
}

int fpc_enrollment_quality_profile300(int32_t quality28, int32_t quality32,
                                      int32_t quality16, int32_t accepted_count,
                                      float area, float normalized_motion,
                                      float relative_area_change,
                                      fpc_enrollment_quality_state *state,
                                      uint64_t *rejection_flags) {
    if (!state || !rejection_flags || accepted_count<0 || accepted_count>80 ||
        !(area>=0.0f) || !(normalized_motion>=0.0f) || !(relative_area_change>=0.0f)) return -1;
    uint64_t flags=(quality28<25?UINT64_C(1):0) |
                   (quality32<60?UINT64_C(16):0) |
                   (quality16<32?UINT64_C(32768):0);
    *rejection_flags=flags;
    state->attempts=(uint16_t)(state->attempts+1u);
    if (!flags) {state->rejection_streak=0;return 0;}
    if (fpc_enrollment_progress_profile300(accepted_count,area,normalized_motion,
        relative_area_change,&state->early_complete_latched,&state->progress)) return -1;
    state->rejection_streak=(uint8_t)(state->rejection_streak+1u);
    return state->rejection_streak>=10?112:0;
}

int fpc_count_packed_mask(const uint32_t *words, size_t width, size_t height,
                           size_t stride_bits, uint32_t *count) {
    if (!words || !count || !width || width>SIZE_MAX-31 || stride_bits!=((width+31)&~(size_t)31) ||
        height>SIZE_MAX/(stride_bits/32) || width>UINT32_MAX || height>UINT32_MAX/width) return -1;
    uint32_t total=0;
    for (size_t y=0;y<height;++y) for (size_t x=0;x<width;x+=32) {
        uint32_t value=words[y*(stride_bits/32)+x/32];
        size_t remaining=width-x;
        if (remaining<32) value&=(UINT32_C(1)<<(unsigned)remaining)-1;
        total+=popcount32(value);
    }
    *count=total;return 0;
}

int fpc_union_packed_mask(uint32_t *destination, size_t width, size_t height,
                           size_t stride_bits, const uint32_t *source,
                           size_t source_width, size_t source_height, size_t source_stride_bits,
                           size_t offset_x, size_t offset_y) {
    if (!destination || !source || !width || !source_width || stride_bits%32 || source_stride_bits%32 ||
        stride_bits<width || source_stride_bits<source_width || offset_x>width || offset_y>height ||
        source_width>width-offset_x || source_height>height-offset_y ||
        !stride_bits || !source_stride_bits || height>SIZE_MAX/stride_bits || source_height>SIZE_MAX/source_stride_bits) return -1;
    for (size_t y=0;y<source_height;++y) for (size_t x=0;x<source_width;++x) {
        size_t src=y*source_stride_bits+x,dst=(y+offset_y)*stride_bits+x+offset_x;
        destination[dst/32]|=((source[src/32]>>(src%32))&1u)<<(dst%32);
    }
    return 0;
}

int fpc_warp_packed_mask(const uint32_t *source, size_t source_width, size_t source_height,
                          size_t source_stride_bits, uint32_t *destination,
                          size_t width, size_t height, size_t stride_bits,
                          const float affine[6], uint8_t outside) {
    if (!source || !destination || !affine || !width || !source_width || source_stride_bits%32 ||
        stride_bits%32 || source_stride_bits<source_width || stride_bits<width ||
        !stride_bits || !source_stride_bits || height>SIZE_MAX/stride_bits || source_height>SIZE_MAX/source_stride_bits) return -1;
    uint32_t q[6];
    for (unsigned i=0;i<6;++i) {
        float value=affine[i]*1048576.0f;
        if (!(value>=-2147483648.0f && value<2147483648.0f)) return -1;
        q[i]=(uint32_t)(int32_t)value;
    }
    uint32_t row_x=q[2]+0x80000u,row_y=q[5]+0x80000u;
    for (size_t y=0;y<height;++y) {
        uint32_t vx=row_x,vy=row_y,word=0;
        for (size_t x=0;x<width;++x) {
            int64_t sx=shift_floor(signed_u32(vx),20),sy=shift_floor(signed_u32(vy),20);
            uint32_t bit=outside&1u;
            if (sx>=0 && sy>=0 && (uint64_t)sx<source_width && (uint64_t)sy<source_height) {
                size_t index=(size_t)sy*source_stride_bits+(size_t)sx;
                bit=(source[index/32]>>(index%32))&1u;
            }
            if (!(x%32)) word=0;
            word|=bit<<(x%32);destination[y*(stride_bits/32)+x/32]=word;
            vx+=q[0];vy+=q[3];
        }
        row_x+=q[1];row_y+=q[4];
    }
    return 0;
}

int fpc_inverse_transform3(const float a[9], float out[9]) {
    if (!a || !out) return -1;
    float det=((a[0]*a[4])*a[8]+(a[1]*a[5])*a[6])+(a[2]*a[3])*a[7];
    det=det-(a[2]*a[4])*a[6];det=det-(a[3]*a[1])*a[8];det=det-(a[0]*a[5])*a[7];
    if (det==0.0f) return -1;
    float inv=1.0f/det,v[9];
    v[0]=(a[8]*a[4]-a[7]*a[5])*inv;
    v[3]=-((a[3]*a[8]-a[6]*a[5])*inv);
    v[6]=(a[3]*a[7]-a[6]*a[4])*inv;
    v[1]=-((a[8]*a[1]-a[2]*a[7])*inv);
    v[4]=(a[8]*a[0]-a[6]*a[2])*inv;
    v[7]=-((a[7]*a[0]-a[6]*a[1])*inv);
    v[2]=(a[1]*a[5]-a[4]*a[2])*inv;
    v[5]=-((a[0]*a[5]-a[2]*a[3])*inv);
    v[8]=(a[4]*a[0]-a[3]*a[1])*inv;
    memcpy(out,v,sizeof(v));return 0;
}

int fpc_compose_transform3(const float a[9], const float b[9], float out[9]) {
    if (!a || !b || !out) return -1;
    float v[9];
    for (unsigned row=0;row<3;++row) for (unsigned col=0;col<3;++col) {
        float value=b[col]*a[row*3]+0.0f;
        value=b[col+3]*a[row*3+1]+value;
        v[row*3+col]=b[col+6]*a[row*3+2]+value;
    }
    memcpy(out,v,sizeof(v));return 0;
}

int fpc_inverse_affine6(const float a[6], float out[6]) {
    if (!a || !out) return -1;
    float det=a[4]*a[0]-a[3]*a[1],v[6];
    if (det==0.0f) return -1;
    v[0]=a[4]/det;v[1]=-(a[1]/det);
    v[2]=(a[5]*a[1]-a[4]*a[2])/det;
    v[3]=-(a[3]/det);v[4]=a[0]/det;
    v[5]=-((a[5]*a[0]-a[3]*a[2])/det);
    memcpy(out,v,sizeof(v));return 0;
}

int fpc_clip_affine_warp_bounds(const float affine[6], int32_t source_width,
                                int32_t source_height, int32_t canvas_width,
                                int32_t canvas_height, int32_t bounds[4], float local[6]) {
    if (!affine || !bounds || !local || source_width<1 || source_height<1 ||
        canvas_width<1 || canvas_height<1) return -1;
    float inv[6];if (fpc_inverse_affine6(affine,inv)) return -1;
    float w=(float)(source_width-1),h=(float)(source_height-1);
    float x[4]={inv[0]*0.0f+inv[1]*0.0f+inv[2],inv[0]*w+inv[1]*0.0f+inv[2],
                inv[1]*h+inv[0]*w+inv[2],inv[1]*h+inv[0]*0.0f+inv[2]};
    float y[4]={inv[3]*0.0f+inv[4]*0.0f+inv[5],inv[3]*w+inv[4]*0.0f+inv[5],
                inv[4]*h+inv[3]*w+inv[5],inv[4]*h+inv[3]*0.0f+inv[5]};
    float xmin=x[0],xmax=x[0],ymin=y[0],ymax=y[0];
    for (unsigned i=0;i<4;++i) {
        if (!(x[i]>=-2147483648.0f && x[i]<2147483520.0f &&
              y[i]>=-2147483648.0f && y[i]<2147483520.0f)) return -1;
        if (x[i]<xmin) xmin=x[i];
        if (x[i]>xmax) xmax=x[i];
        if (y[i]<ymin) ymin=y[i];
        if (y[i]>ymax) ymax=y[i];
    }
    int32_t left=(int32_t)xmin,top=(int32_t)ymin,right=(int32_t)xmax+1,bottom=(int32_t)ymax+1;
    if (left<0) left=0;
    if (top<0) top=0;
    if (right>canvas_width-1) right=canvas_width-1;
    if (bottom>canvas_height-1) bottom=canvas_height-1;
    int64_t width=(int64_t)right-left+1,height=(int64_t)bottom-top+1;
    bounds[0]=left;bounds[1]=top;bounds[2]=width<0?0:(int32_t)width;bounds[3]=height<0?0:(int32_t)height;
    memcpy(local,affine,6*sizeof(float));
    local[2]=((float)left*affine[0]+(float)top*affine[1])+affine[2];
    local[5]=((float)top*affine[4]+(float)left*affine[3])+affine[5];
    return 0;
}

float fpc_atan2_approx_float(float sine, float cosine) {
    float a=sine,b=cosine,offset=0.0f;
    if (sine<0.0f) {offset=-3.1415927f;a=-sine;b=-cosine;}
    if (b<0.0f) {offset=offset+1.5707964f;float old=b;b=a;a=-old;}
    if (a>b) {offset=offset+0.78539819f;b=b+a;a=(a+a)-b;}
    float t=(a*0.9238795f-b*0.38268343f)/(b*0.9238795f+a*0.38268343f);
    float square=t*t;
    float value=0.11111111f-square*0.090909094f;
    value=value*square-0.14285715f;value=value*square+0.2f;
    value=value*square-0.33333334f;value=value*square+1.0f;
    return value*t+(offset+0.39269909f);
}

int fpc_transform_to_parameters(const float matrix[9], float parameters[4]) {
    if (!matrix || !parameters) return -1;
    float scale=fpc_sqrt_recovered(matrix[4]*matrix[0]-matrix[1]*matrix[3]);
    parameters[0]=matrix[2];parameters[1]=matrix[5];parameters[3]=scale;
    parameters[2]=fpc_atan2_approx_float(matrix[3]/scale,matrix[0]/scale);
    return 0;
}

int fpc_parameters_to_transform(const float parameters[4], float matrix[9]) {
    if (!parameters || !matrix) return -1;
    float c,s;if (fpc_sincos_recovered(parameters[2],&c,&s)) return -1;
    c=c*parameters[3];s=s*parameters[3];
    float value[9]={c,-s,parameters[0],s,c,parameters[1],0,0,1};
    memcpy(matrix,value,sizeof(value));return 0;
}

void fpc_q14_similarity_to_transform(const int16_t fixed[4], float matrix[9]) {
    float c=(float)fixed[0]*0.00006103515625f,s=(float)fixed[1]*0.00006103515625f;
    float value[9]={c,-s,(float)fixed[2]*0.0625f,s,c,(float)fixed[3]*0.0625f,0,0,1};
    memcpy(matrix,value,sizeof(value));
}

int fpc_weighted_group_transform(const fpc_capture_match *matches, size_t match_count,
                                  size_t count, size_t capture, const int16_t *groups,
                                  const float *transforms, float output[9]) {
    if (!output || !groups || !transforms || count>32767 || capture>=count ||
        match_count<count*(count-1)/2 || (match_count && !matches)) return -1;
    float sum[4]={0,0,0,0};uint32_t weight_sum=0;
    for (size_t later=1;later<count;++later) for (size_t earlier=0;earlier<later;++earlier) {
        const fpc_capture_match *pair=matches+later*(later-1)/2+earlier;
        if (!pair->success || !((later==capture && groups[earlier]!=-1) ||
                               (earlier==capture && groups[later]!=-1))) continue;
        float matrix[9],composed[9],inverse[9],parameters[4];
        fpc_q14_similarity_to_transform(pair->transform,matrix);
        if (groups[earlier]!=-1 && fpc_compose_transform3(transforms+earlier*9,matrix,composed)) return -1;
        if (groups[later]!=-1) {
            if (fpc_inverse_transform3(matrix,inverse) ||
                fpc_compose_transform3(transforms+later*9,inverse,composed)) return -1;
        }
        if (fpc_transform_to_parameters(composed,parameters)) return -1;
        float weight=(float)pair->inliers;
        for (unsigned i=0;i<4;++i) sum[i]=sum[i]+parameters[i]*weight;
        weight_sum+=(uint32_t)pair->inliers;
    }
    int64_t total=signed_u32(weight_sum);
    if (total) for (unsigned i=0;i<4;++i) sum[i]=sum[i]/(float)total;
    return fpc_parameters_to_transform(sum,output);
}

int fpc_capture_group_bounds(const int32_t *widths, const int32_t *heights,
                              const int16_t *groups, const float *transforms,
                              size_t count, int32_t group, int32_t bounds[4]) {
    if (!widths || !heights || !groups || !transforms || !bounds || count>32767) return -1;
    static const unsigned corners[4][2]={{0,0},{1,0},{1,1},{0,1}};
    int32_t xmin=INT32_MAX,ymin=INT32_MAX,xmax=INT32_MIN,ymax=INT32_MIN;int found=0;
    for (size_t i=0;i<count;++i) {
        if (groups[i]==-1 || (group>=0 && groups[i]!=group)) continue;
        if (widths[i]<1 || heights[i]<1) return -1;
        float inverse[9];if (fpc_inverse_transform3(transforms+i*9,inverse)) return -1;
        for (unsigned corner=0;corner<4;++corner) {
            float x=(float)(widths[i]-1)*(float)corners[corner][0];
            float y=(float)(heights[i]-1)*(float)corners[corner][1];
            float divisor=(x*inverse[6]+y*inverse[7])+inverse[8];
            if (divisor==0.0f) return -1;
            float tx=((y*inverse[1]+x*inverse[0])+inverse[2])/divisor;
            float ty=((x*inverse[3]+y*inverse[4])+inverse[5])/divisor;
            if (!(tx>=-2147483648.0f && tx<2147483648.0f && ty>=-2147483648.0f && ty<2147483648.0f)) return -1;
            if ((float)xmin>tx) xmin=(int32_t)tx;
            if (tx>(float)xmax) xmax=(int32_t)tx;
            if ((float)ymin>ty) ymin=(int32_t)ty;
            if (ty>(float)ymax) ymax=(int32_t)ty;
            found=1;
        }
    }
    if (!found) return -1;
    bounds[0]=xmin;bounds[1]=ymin;
    bounds[2]=(int32_t)signed_u32((uint32_t)xmax-(uint32_t)xmin+1u);
    bounds[3]=(int32_t)signed_u32((uint32_t)ymax-(uint32_t)ymin+1u);
    return 0;
}

int fpc_rebuild_capture_groups(const fpc_capture_match *matches, size_t match_count,
                               size_t count, const int32_t *widths, const int32_t *heights,
                               int32_t minimum_group_size, int preserve_transforms,
                               int16_t *groups, uint16_t *roots, float *transforms,
                               fpc_capture_groups_state *state, uint32_t *flags) {
    if (!state || !flags || !groups || !roots || !transforms || !widths || !heights ||
        !count || count>32767 || match_count<count*(count-1)/2 || (match_count && !matches)) return -1;
    uint8_t *visited=calloc(count,1);uint32_t *weights=calloc(count,sizeof(*weights));
    if (!visited || !weights) {free(visited);free(weights);return -1;}
    for (size_t i=0;i<count;++i) groups[i]=-1;
    int32_t group=-1;
    for (;;) {
        memset(weights,0,count*sizeof(*weights));
        for (size_t later=1;later<count;++later) for (size_t earlier=0;earlier<later;++earlier) {
            const fpc_capture_match *pair=matches+later*(later-1)/2+earlier;
            if (pair->success) {
                if (!visited[later]) weights[later]+=(uint32_t)pair->inliers;
                if (!visited[earlier]) weights[earlier]+=(uint32_t)pair->inliers;
            }
        }
        int64_t maximum=0;size_t selected=count;
        for (size_t i=0;i<count;++i) if (signed_u32(weights[i])>maximum) {maximum=signed_u32(weights[i]);selected=i;}
        if (selected==count) break;
        visited[selected]=1;roots[++group]=(uint16_t)selected;groups[selected]=(int16_t)group;
        static const float identity[9]={1,0,0,0,1,0,0,0,1};
        memcpy(transforms+selected*9,identity,sizeof(identity));
        for (;;) {
            memset(weights,0,count*sizeof(*weights));
            for (size_t later=1;later<count;++later) for (size_t earlier=0;earlier<later;++earlier) {
                const fpc_capture_match *pair=matches+later*(later-1)/2+earlier;
                if (pair->success) {
                    if (!visited[later] && groups[earlier]!=-1) weights[later]+=(uint32_t)pair->inliers;
                    if (!visited[earlier] && groups[later]!=-1) weights[earlier]+=(uint32_t)pair->inliers;
                }
            }
            maximum=0;selected=count;
            for (size_t i=0;i<count;++i) if (signed_u32(weights[i])>maximum) {maximum=signed_u32(weights[i]);selected=i;}
            if (selected==count) break;
            visited[selected]=1;
            if (!preserve_transforms || groups[selected]!=group) {
                if (fpc_weighted_group_transform(matches,match_count,count,selected,groups,transforms,transforms+selected*9)) {
                    free(visited);free(weights);return -1;
                }
                groups[selected]=(int16_t)group;
            }
        }
    }
    state->group_count=group+1;
    if (state->selected_group==-1) {
        for (int32_t g=0;g<state->group_count;++g) {
            int32_t members=0;
            for (size_t i=0;i<count;++i) members+=groups[i]==g;
            if (members>=minimum_group_size) {
                int32_t bounds[4];
                if (fpc_capture_group_bounds(widths,heights,groups,transforms,count,g,bounds)) {free(visited);free(weights);return -1;}
                state->selected_group=g;state->reference_capture=roots[g];*flags|=0x20u;
                state->center_x=(float)bounds[2]*0.5f+(float)bounds[0];
                state->center_y=(float)bounds[3]*0.5f+(float)bounds[1];
            }
        }
    } else {
        state->selected_group=-1;
        for (size_t i=0;i<count && state->selected_group==-1;++i)
            if ((int32_t)i==state->reference_capture && groups[i]>=0) {
                state->selected_group=groups[i];roots[groups[i]]=(uint16_t)i;
            }
        if (state->selected_group==-1) {state->selected_group=0;state->reference_capture=roots[0];}
    }
    free(visited);free(weights);return 0;
}

int fpc_capture_canvas_transform(const float *transforms, size_t count, size_t capture,
                                  uint16_t reference, int32_t reference_width,
                                  int32_t reference_height, int32_t canvas_width,
                                  int32_t canvas_height, float output[9]) {
    if (!transforms || !output || capture>=count || canvas_width<1 || canvas_height<1 ||
        (reference!=UINT16_MAX && (reference>=count || reference_width<1 || reference_height<1))) return -1;
    float root[9]={1,0,0,0,1,0,0,0,1},translation[9]={1,0,0,0,1,0,0,0,1},inverse[9],relative[9];
    translation[2]=(float)canvas_width*0.5f;translation[5]=(float)canvas_height*0.5f;
    if (reference!=UINT16_MAX) {
        memcpy(root,transforms+(size_t)reference*9,sizeof(root));
        translation[2]=translation[2]-(float)reference_width*0.5f;
        translation[5]=translation[5]-(float)reference_height*0.5f;
    }
    if (fpc_inverse_transform3(transforms+capture*9,inverse) ||
        fpc_compose_transform3(root,inverse,relative)) return -1;
    return fpc_compose_transform3(translation,relative,output);
}

int fpc_normalize_group_canvas(const int32_t *widths, const int32_t *heights,
                                const int16_t *groups, const uint16_t *roots,
                                size_t count, int32_t canvas_width,
                                int32_t canvas_height, float *transforms) {
    if (count>80 || (count && (!widths || !heights || !groups || !roots || !transforms))) return -1;
    if (!count) return 0;
    float *replacement=malloc(count*9*sizeof(*replacement));
    if (!replacement) return 2;
    for (size_t i=0;i<count;++i) if (groups[i]!=-1) {
        if (groups[i]<0 || (size_t)groups[i]>=count) {free(replacement);return -1;}
        uint16_t root=roots[(size_t)groups[i]];float matrix[9];
        if ((root!=UINT16_MAX && root>=count) ||
            fpc_capture_canvas_transform(transforms,count,i,root,root==UINT16_MAX?0:widths[root],
                root==UINT16_MAX?0:heights[root],canvas_width,canvas_height,matrix) ||
            fpc_inverse_transform3(matrix,replacement+9*i)) {free(replacement);return -1;}
    }
    for (size_t i=0;i<count;++i) if (groups[i]!=-1) memcpy(transforms+9*i,replacement+9*i,9*sizeof(float));
    free(replacement);return 0;
}

int fpc_build_group_mask_union(const fpc_capture_coverage *captures, size_t count,
                                const int16_t *groups, const uint16_t *roots,
                                const float *transforms, int16_t group,
                                int32_t canvas_width, int32_t canvas_height,
                                uint32_t *output, size_t output_words) {
    if (!captures || !groups || !roots || !transforms || !output || group<0 ||
        (size_t)group>=count || count>32767 || canvas_width<1 || canvas_height<1 || canvas_width>INT32_MAX-31) return -1;
    size_t stride=((size_t)canvas_width+31)&~(size_t)31;
    if ((size_t)canvas_height>SIZE_MAX/(stride/32) || output_words<(stride/32)*(size_t)canvas_height) return -1;
    memset(output,0,(stride/32)*(size_t)canvas_height*sizeof(*output));
    uint16_t root=roots[group];if (root!=UINT16_MAX && root>=count) return -1;
    for (size_t i=0;i<count;++i) if (groups[i]==group) {
        const fpc_capture_coverage *capture=captures+i;
        float canvas[9],inverse[9],local[6];int32_t bounds[4];
        if (fpc_capture_canvas_transform(transforms,count,i,root,root==UINT16_MAX?0:captures[root].image_width,
                                        root==UINT16_MAX?0:captures[root].image_height,canvas_width,canvas_height,canvas) ||
            fpc_inverse_transform3(canvas,inverse) ||
            fpc_clip_affine_warp_bounds(inverse,capture->mask_width,capture->mask_height,canvas_width,canvas_height,bounds,local)) return -1;
        if (!bounds[2] || !bounds[3]) continue;
        size_t local_stride=((size_t)bounds[2]+31)&~(size_t)31;
        if ((size_t)bounds[3]>SIZE_MAX/(local_stride/32)/sizeof(uint32_t)) return -1;
        uint32_t *warped=calloc((local_stride/32)*(size_t)bounds[3],sizeof(*warped));if (!warped) return -1;
        int status=fpc_warp_packed_mask(capture->mask,capture->mask_width,capture->mask_height,capture->mask_stride_bits,
                                       warped,(size_t)bounds[2],(size_t)bounds[3],local_stride,local,0);
        if (!status) status=fpc_union_packed_mask(output,canvas_width,canvas_height,stride,warped,bounds[2],bounds[3],
                                                 local_stride,bounds[0],bounds[1]);
        free(warped);if (status) return status;
    }
    return 0;
}

int fpc_update_enrollment_metrics(size_t count, float area, int32_t image_width,
                                   int32_t image_height, const fpc_capture_match *matches,
                                   size_t match_count, fpc_enrollment_metrics *state) {
    if (!state || !count || count>80 || !(area>0.0f) || image_width<1 || image_height<1 ||
        match_count<count*(count-1)/2 || (match_count && !matches)) return -1;
    state->area[count-1]=area;
    if (count<2) return 0;
    float change=state->area[count-1]-state->area[count-2];if (change<0) change=-change;
    float normalizer=1.0f;
    if (count>=3) {
        float previous=state->area[count-2]-state->area[count-3];if (previous<0) previous=-previous;
        normalizer=1.6700001f;change=previous*0.67000002f+change;
        if (count>=4) {
            float older=state->area[count-3]-state->area[count-4];if (older<0) older=-older;
            normalizer=2.0f;change=older*0.33000001f+change;
        }
    }
    state->relative_area_change=change/(normalizer*area);
    uint32_t diagonal=(uint32_t)image_height*(uint32_t)image_height+(uint32_t)image_width*(uint32_t)image_width;
    float fallback=fpc_sqrt_recovered((float)signed_u32(diagonal)),motion=0.0f;
    int32_t n=(int32_t)count,start=1-n;if (start<=-3) start=-3;
    for (int32_t later=start;later<0;++later) {
        int32_t earlier=-n;if (earlier<-4) earlier=-4;
        int32_t end=later<-1?later:-1;
        for (;earlier<end;++earlier) {
            size_t index=(size_t)(earlier+n)+(size_t)(n+later)*(size_t)(n+later-1)/2;
            const fpc_capture_match *pair=matches+index;float distance=fallback;
            if (pair->success) {
                float x=(float)pair->transform[2]*0.0625f,y=(float)pair->transform[3]*0.0625f;
                distance=fpc_sqrt_recovered(y*y+x*x);
            }
            motion=((float)earlier+((float)later+8.0f))*distance+motion;
            if (later==-1 && earlier==-2) state->latest_motion=distance;
        }
    }
    float divisor=count==2?5.0f:count==3?12.0f:18.0f;
    state->motion[count-1]=motion/divisor;
    state->normalized_motion=state->motion[count-1]/fpc_sqrt_recovered(area);
    return 0;
}

int fpc_compute_enrollment_metrics(const fpc_capture_coverage *captures, size_t count,
                                    const int32_t *coverage_percent, const int16_t *groups,
                                    const uint16_t *roots, const float *transforms,
                                    size_t group_count, int32_t canvas_width, int32_t canvas_height,
                                    const fpc_capture_match *matches, size_t match_count,
                                    fpc_enrollment_metrics *state) {
    if (!captures || !coverage_percent || !groups || !roots || !transforms || !state ||
        !count || count>80 || group_count>count || canvas_width<1 || canvas_width>INT32_MAX-31 || canvas_height<1) return -1;
    size_t stride=((size_t)canvas_width+31)&~(size_t)31;
    if ((size_t)canvas_height>SIZE_MAX/(stride/32)/sizeof(uint32_t)) return -1;
    size_t words=(stride/32)*(size_t)canvas_height;
    uint32_t *mask=calloc(words,sizeof(*mask));if (!mask) return -1;
    float aligned=0.0f,unaligned=0.0f;
    for (size_t g=0;g<group_count;++g) {
        uint32_t area=0;
        if (fpc_build_group_mask_union(captures,count,groups,roots,transforms,(int16_t)g,canvas_width,canvas_height,mask,words) ||
            fpc_count_packed_mask(mask,canvas_width,canvas_height,stride,&area)) {free(mask);return -1;}
        aligned=aligned+(float)signed_u32(area);
    }
    free(mask);
    uint32_t pixels=(uint32_t)captures[0].image_width*(uint32_t)captures[0].image_height;
    for (size_t i=0;i<count;++i) if (groups[i]<0)
        unaligned=unaligned+(((float)coverage_percent[i]/100.0f)*(float)signed_u32(pixels))*0.5f;
    return fpc_update_enrollment_metrics(count,aligned+unaligned,captures[0].image_width,
                                         captures[0].image_height,matches,match_count,state);
}
