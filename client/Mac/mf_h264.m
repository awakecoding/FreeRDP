/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * AV Foundation Framework H.264 Support
 *
 * Copyright 2015 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mfreerdp.h"

#include <freerdp/codec/h264.h>

#include <Foundation/Foundation.h>
#include <AVFoundation/AVFoundation.h>
#include <VideoToolbox/VideoToolbox.h>

struct _H264_CONTEXT_AV
{
	BYTE* sps_data;
	UINT32 sps_size;
	BYTE* pps_data;
	UINT32 pps_size;
	BYTE* avcc_data;
	UINT32 avcc_size;
	CMBlockBufferRef blockBuffer;
	CMSampleBufferRef sampleBuffer;
	VTDecompressionSessionRef session;
	CMFormatDescriptionRef formatDescription;
	struct h264_sequence_parameter_set sps;
	struct h264_picture_parameter_set pps;
};
typedef struct _H264_CONTEXT_AV H264_CONTEXT_AV;

static void av_output_callback(void* decompressionOutputRefCon, void* sourceFrameRefCon, OSStatus status, VTDecodeInfoFlags infoFlags,
			       CVImageBufferRef imageBuffer, CMTime presentationTimeStamp, CMTime presentationDuration)
{
	if (status != noErr)
		return;
	
	if (!imageBuffer)
		return;
}

int av_dummy_h264(H264_CONTEXT* h264, BYTE* data, UINT32 size)
{
	OSStatus status;
	H264_CONTEXT_AV* sys = (H264_CONTEXT_AV*) h264->pSystemData;

	if (!sys->session)
	{
		VTDecompressionOutputCallbackRecord outputCallback = { av_output_callback, h264 };
	
		NSDictionary* pixelBufferAttributes = @{(NSString*)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA)};
	
		status = VTDecompressionSessionCreate(kCFAllocatorDefault, sys->formatDescription, NULL,
					      (CFDictionaryRef) pixelBufferAttributes, &outputCallback, &sys->session);
	
		if (status != noErr)
			return -1;
	}
	
	status = CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault, NULL, size,
						    kCFAllocatorDefault, NULL, 0, size, 0, &sys->blockBuffer);
	
	if (status != noErr)
		return -1;
	
	status = CMBlockBufferReplaceDataBytes(data, sys->blockBuffer, 0, size);
	
	if (status != noErr)
		return -1;
	
	status = CMSampleBufferCreate(kCFAllocatorDefault, sys->blockBuffer, true, NULL, NULL,
				      sys->formatDescription, 1, 0, NULL, 0, NULL, &sys->sampleBuffer);

	if (status != noErr)
		return -1;
	
	status = VTDecompressionSessionDecodeFrame(sys->session, sys->sampleBuffer, 0, NULL, NULL);
	
	if (status != noErr)
		return -1;
	
	if (sys->blockBuffer)
	{
		CFRelease(sys->blockBuffer);
		sys->blockBuffer = NULL;
	}
	
	if (sys->sampleBuffer)
	{
		CFRelease(sys->sampleBuffer);
		sys->sampleBuffer = NULL;
	}
	
	return 1;
}

static int av_create_format_description(H264_CONTEXT* h264)
{
	BYTE* p;
	OSStatus status;
	H264_CONTEXT_AV* sys = (H264_CONTEXT_AV*) h264->pSystemData;
	struct h264_sequence_parameter_set* sps = &sys->sps;
	
	sys->avcc_size = 11 + sys->sps_size + sys->pps_size;
	sys->avcc_data = realloc(sys->avcc_data, sys->avcc_size);
	
	if (!sys->avcc_data)
		return -1;
	
	p = sys->avcc_data;
	
	p[0] = 0x01;
	p[1] = sps->profile_idc;
	p[2] = ((sps->constraint_set0_flag << 7) | (sps->constraint_set1_flag << 6) | (sps->constraint_set2_flag << 5) | /* avc compatibility */
		(sps->constraint_set3_flag << 4) | (sps->constraint_set4_flag << 3) | (sps->constraint_set5_flag << 2) | sps->reserved_zero_2bits);
	p[3] = sps->level_idc;
	p[4] = 0xFC | 0x3;
	p[5] = 0xE0 | 0x1;
	p += 6;
	p[0] = (sys->sps_size >> 8) & 0xFF;
	p[1] = (sys->sps_size) & 0xFF;
	CopyMemory(&p[2], sys->sps_data, sys->sps_size);
	p += 2 + sys->sps_size;
	p[0] = (sys->pps_size >> 8) & 0xFF;
	p[1] = (sys->pps_size) & 0xFF;
	CopyMemory(&p[2], sys->pps_data, sys->pps_size);
	p += 2 + sys->pps_size;
	
	const char* avcC = "avcC";
	const CFStringRef avcCKey = CFStringCreateWithCString(kCFAllocatorDefault, avcC, kCFStringEncodingUTF8);
	const CFDataRef avcCValue = CFDataCreate(kCFAllocatorDefault, sys->avcc_data, sys->avcc_size);
	const void* atomDictKeys[] = { avcCKey };
	const void* atomDictValues[] = { avcCValue };
	CFDictionaryRef atomsDict = CFDictionaryCreate(kCFAllocatorDefault, atomDictKeys, atomDictValues, 1, nil, nil);
	const void* extensionDictKeys[] = { kCMFormatDescriptionExtension_SampleDescriptionExtensionAtoms };
	const void* extensionDictValues[] = { atomsDict };
	CFDictionaryRef extensionDict = CFDictionaryCreate(kCFAllocatorDefault, extensionDictKeys, extensionDictValues, 1, nil, nil);
	
	status = CMVideoFormatDescriptionCreate(kCFAllocatorDefault, kCMVideoCodecType_H264,
						h264->width, h264->height, (CFDictionaryRef) extensionDict, &sys->formatDescription);
	
	if (status != noErr)
		return -1;
	
	return 1;
}

static int av_decompress(H264_CONTEXT* h264, BYTE* pSrcData, UINT32 SrcSize)
{
	BYTE* p;
	int nal_unit_index;
	int nal_unit_count;
	struct h264_byte_stream_nal_unit* nal;
	struct h264_byte_stream_nal_unit* nal_units = NULL;
	H264_CONTEXT_AV* sys = (H264_CONTEXT_AV*) h264->pSystemData;
	
	if (!sys)
		return -1;
	
	nal_unit_count = h264_parse_nal_units(h264, pSrcData, SrcSize, &nal_units);
	
	if ((nal_unit_count < 0) || !nal_units)
		return -1;
	
	for (nal_unit_index = 0; nal_unit_index < nal_unit_count; nal_unit_index++)
	{
		nal = &nal_units[nal_unit_index];
		
		if (nal->unit_type == 7) /* sequence parameter set */
		{
			struct h264_sequence_parameter_set* sps = &sys->sps;
			
			h264_parse_sequence_parameter_set(sps, nal->body_data, nal->body_size);
			
			/**
			 * Fetching the dimensions of an H.264 video stream:
			 * http://stackoverflow.com/questions/6394874/fetching-the-dimensions-of-a-h264video-stream
			 */
			
			h264->width = ((sps->pic_width_in_mbs_minus1 + 1) * 16) -
				(sps->frame_crop_left_offset * 2) - (sps->frame_crop_right_offset * 2);
			
			h264->height= ((2 - sps->frame_mbs_only_flag) * (sps->pic_height_in_map_units_minus1 + 1) * 16) -
				(sps->frame_crop_top_offset * 2) - (sps->frame_crop_bottom_offset * 2);
			
			sys->sps_size = nal->unit_size;
			sys->sps_data = realloc(sys->sps_data, sys->sps_size);
			
			if (!sys->sps_data)
				return -1;
			
			CopyMemory(sys->sps_data, nal->header_data, sys->sps_size);
		}
		else if (nal->unit_type == 8) /* picture parameter set */
		{
			struct h264_picture_parameter_set* pps = &sys->pps;
			
			h264_parse_picture_parameter_set(pps, nal->body_data, nal->body_size);
			
			sys->pps_size = nal->unit_size;
			sys->pps_data = realloc(sys->pps_data, sys->pps_size);
			
			if (!sys->pps_data)
				return -1;
			
			CopyMemory(sys->pps_data, nal->header_data, sys->pps_size);
			
			if (av_create_format_description(h264) < 0)
			{
				fprintf(stderr, "av_create_format_description_failure\n");
				return -1;
			}
		}
		
		p = nal->header_data - 4;
		
		if (p >= pSrcData)
		{
			/* overwrite start marker with big-endian NAL size */
			p[0] = (nal->unit_size >> 24) & 0xFF;
			p[1] = (nal->unit_size >> 16) & 0xFF;
			p[2] = (nal->unit_size >> 8) & 0xFF;
			p[3] = (nal->unit_size) & 0xFF;
		}
		
		fprintf(stderr, "[%02d] size: %d type: %d %s\n",
			nal_unit_index, nal->unit_size, nal->unit_type, h264_get_nal_unit_name(nal->unit_type));
	}
	
	free(nal_units);
	
	return 1;
}

static int av_compress(H264_CONTEXT* h264, BYTE** ppDstData, UINT32* pDstSize)
{
	H264_CONTEXT_AV* sys = (H264_CONTEXT_AV*) h264->pSystemData;
	
	if (!sys)
		return -1;
	
	return 1;
}

static void av_uninit(H264_CONTEXT* h264)
{
	H264_CONTEXT_AV* sys = (H264_CONTEXT_AV*) h264->pSystemData;
	
	if (sys)
	{
		if (sys->formatDescription)
		{
			CFRelease(sys->formatDescription);
			sys->formatDescription = NULL;
		}
		
		if (sys->session)
		{
			VTDecompressionSessionInvalidate(sys->session);
			CFRelease(sys->session);
			sys->session = NULL;
		}
		
		if (sys->sps_data)
		{
			free(sys->sps_data);
			sys->sps_data = NULL;
		}
		
		if (sys->pps_data)
		{
			free(sys->pps_data);
			sys->pps_data = NULL;
		}
		
		free(sys);
		h264->pSystemData = NULL;
	}
}

static BOOL av_init(H264_CONTEXT* h264)
{
	H264_CONTEXT_AV* sys;
	
	sys = (H264_CONTEXT_AV*) calloc(1, sizeof(H264_CONTEXT_AV));
	
	if (!sys)
		return FALSE;
	
	h264->pSystemData = (void*) sys;
	
	return TRUE;
}

H264_CONTEXT_SUBSYSTEM g_Subsystem_AV =
{
	"AV Foundation",
	av_init,
	av_uninit,
	av_decompress,
	av_compress
};

void mac_h264_init()
{
	h264_set_custom_subsystem(&g_Subsystem_AV);
}
