/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * H.264 Bitmap Compression
 *
 * Copyright 2014 Mike McDonald <Mike.McDonald@software.dell.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_CODEC_H264_H
#define FREERDP_CODEC_H264_H

#include <freerdp/api.h>
#include <freerdp/types.h>
#include <freerdp/channels/rdpgfx.h>

typedef struct _H264_CONTEXT H264_CONTEXT;

typedef BOOL (*pfnH264SubsystemInit)(H264_CONTEXT* h264);
typedef void (*pfnH264SubsystemUninit)(H264_CONTEXT* h264);

typedef int (*pfnH264SubsystemDecompress)(H264_CONTEXT* h264, BYTE* pSrcData, UINT32 SrcSize);
typedef int (*pfnH264SubsystemCompress)(H264_CONTEXT* h264, BYTE** ppDstData, UINT32* pDstSize);

struct _H264_CONTEXT_SUBSYSTEM
{
	const char* name;
	pfnH264SubsystemInit Init;
	pfnH264SubsystemUninit Uninit;
	pfnH264SubsystemDecompress Decompress;
	pfnH264SubsystemCompress Compress;
};
typedef struct _H264_CONTEXT_SUBSYSTEM H264_CONTEXT_SUBSYSTEM;

enum _H264_RATECONTROL_MODE
{
	H264_RATECONTROL_VBR = 0,
	H264_RATECONTROL_CQP
};
typedef enum _H264_RATECONTROL_MODE H264_RATECONTROL_MODE;

struct _H264_CONTEXT
{
	BOOL Compressor;

	UINT32 width;
	UINT32 height;

	H264_RATECONTROL_MODE RateControlMode;
	UINT32 BitRate;
	FLOAT FrameRate;
	UINT32 QP;
	UINT32 NumberOfThreads;
	
	int iStride[3];
	BYTE* pYUVData[3];

	void* pSystemData;
	H264_CONTEXT_SUBSYSTEM* subsystem;
};

struct h264_supplemental_enhancement_information
{
	int payloadType;
	int payloadSize;
};

struct h264_sequence_parameter_set
{
	int profile_idc;
	int constraint_set0_flag;
	int constraint_set1_flag;
	int constraint_set2_flag;
	int constraint_set3_flag;
	int constraint_set4_flag;
	int constraint_set5_flag;
	int reserved_zero_2bits;
	int level_idc;
	int seq_parameter_set_id;
	
	int chroma_format_idc;
	int separate_colour_plane_flag;
	int bit_depth_luma_minus8;
	int bit_depth_chroma_minus8;
	int qpprime_y_zero_transform_bypass_flag;
	int seq_scaling_matrix_present_flag;
	
	int log2_max_frame_num_minus4;
	int pic_order_cnt_type;
	int log2_max_pic_order_cnt_lsb_minus4;
	int delta_pic_order_always_zero_flag;
	int offset_for_non_ref_pic;
	int offset_for_top_to_bottom_field;
	int num_ref_frames_in_pic_order_cnt_cycle;
	
	int max_num_ref_frames;
	int gaps_in_frame_num_value_allowed_flag;
	int pic_width_in_mbs_minus1;
	int pic_height_in_map_units_minus1;
	int frame_mbs_only_flag;
	int mb_adaptive_frame_field_flag;
	int direct_8x8_inference_flag;
	
	int frame_cropping_flag;
	int frame_crop_left_offset;
	int frame_crop_right_offset;
	int frame_crop_top_offset;
	int frame_crop_bottom_offset;
	
	int vui_parameters_present_flag;
};

struct h264_picture_parameter_set
{
	int pic_parameter_set_id;
	int seq_parameter_set_id;
	int entropy_coding_mode_flag;
	int bottom_field_pic_order_in_frame_present_flag;
	int num_slice_groups_minus1;
	int slice_group_map_type;
	int slice_group_change_direction_flag;
	int slice_group_change_rate_minus1;
	int pic_size_in_map_units_minus1;
	
	int num_ref_idx_l0_default_active_minus1;
	int num_ref_idx_l1_default_active_minus1;
	int weighted_pred_flag;
	int weighted_bipred_idc;
	int pic_init_qp_minus26;
	int pic_init_qs_minus26;
	int chroma_qp_index_offset;
	int deblocking_filter_control_present_flag;
	int constrained_intra_pred_flag;
	int redundant_pic_cnt_present_flag;
	
	int transform_8x8_mode_flag;
	int pic_scaling_matrix_present_flag;
	int second_chroma_qp_index_offset;
};

struct h264_access_unit_delimiter
{
	int primary_pic_type;
};

struct h264_nal_unit_header_svc_extension
{
	int idr_flag;
	int priority_id;
	int no_inter_layer_pred_flag;
	int dependency_id;
	int quality_id;
	int temporal_id;
	int use_ref_base_pic_flag;
	int discardable_flag;
	int output_flag;
	int reserved_three_2bits;
};

struct h264_nal_unit_header_mvc_extension
{
	int non_idr_flag;
	int priority_id;
	int view_id;
	int temporal_id;
	int anchor_pic_flag;
	int inter_view_flag;
	int reserved_one_bit;
};

struct h264_byte_stream_nal_unit
{
	int ref_idc;
	int unit_type;
	int unit_size;
	int header_size;
	BYTE* header_data;
	int body_size;
	BYTE* body_data;
	int svc_extension_flag;
	struct h264_nal_unit_header_svc_extension svc;
	struct h264_nal_unit_header_mvc_extension mvc;
};

#ifdef __cplusplus
extern "C" {
#endif

FREERDP_API int h264_compress(H264_CONTEXT* h264, BYTE* pSrcData, DWORD SrcFormat,
		int nSrcStep, int nSrcWidth, int nSrcHeight, BYTE** ppDstData, UINT32* pDstSize);

FREERDP_API int h264_decompress(H264_CONTEXT* h264, BYTE* pSrcData, UINT32 SrcSize,
		BYTE** ppDstData, DWORD DstFormat, int nDstStep, int nDstWidth, int nDstHeight,
		RDPGFX_RECT16* regionRects, int numRegionRect);
	
FREERDP_API void h264_set_custom_subsystem(H264_CONTEXT_SUBSYSTEM* sys);

FREERDP_API int h264_context_reset(H264_CONTEXT* h264);

FREERDP_API H264_CONTEXT* h264_context_new(BOOL Compressor);
FREERDP_API void h264_context_free(H264_CONTEXT* h264);

FREERDP_API int h264_parse(H264_CONTEXT* h264, BYTE* data, UINT32 size);
FREERDP_API int h264_parse_nal_units(H264_CONTEXT* h264, BYTE* data, UINT32 size, struct h264_byte_stream_nal_unit** p_nal_units);

FREERDP_API const char* h264_get_nal_unit_name(int nal_unit_type);
FREERDP_API int h264_parse_supplemental_enhancement_information(struct h264_supplemental_enhancement_information* sei, BYTE* data, UINT32 size);
FREERDP_API int h264_parse_sequence_parameter_set(struct h264_sequence_parameter_set* sps, BYTE* data, UINT32 size);
FREERDP_API int h264_parse_picture_parameter_set(struct h264_picture_parameter_set* pps, BYTE* data, UINT32 size);
FREERDP_API int h264_parse_access_unit_delimiter(struct h264_access_unit_delimiter* aud, BYTE* data, UINT32 size);
FREERDP_API int h264_parse_nal_unit_header_svc_extension(struct h264_nal_unit_header_svc_extension* svc, BYTE* data, UINT32 size);
FREERDP_API int h264_parse_nal_unit_header_mvc_extension(struct h264_nal_unit_header_mvc_extension* mvc, BYTE* data, UINT32 size);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CODEC_H264_H */

