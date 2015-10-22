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

#include <winpr/print.h>

#include <freerdp/log.h>
#include <freerdp/codec/h264.h>

#include <Foundation/Foundation.h>
#include <AVFoundation/AVFoundation.h>
#include <VideoToolbox/VideoToolbox.h>

#define TAG CLIENT_TAG("mac.h264")

struct _H264_CONTEXT_AV
{
	BYTE* sps_data;
	UINT32 sps_size;
	BYTE* pps_data;
	UINT32 pps_size;
	BYTE* avcc_data;
	UINT32 avcc_size;
	UINT32 pic_width;
	UINT32 pic_height;
	BYTE* pic_data;
	UINT32 pic_size;
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
	BYTE* pSrc;
	BYTE* pDst;
	H264_CONTEXT* h264;
	H264_CONTEXT_AV* sys;
	CVPlanarPixelBufferInfo_YCbCrPlanar planes;
	
	if (status != noErr)
		return;
	
	if (!imageBuffer)
		return;
	
	if (!decompressionOutputRefCon)
		return;
	
	h264 = (H264_CONTEXT*) decompressionOutputRefCon;
	sys = (H264_CONTEXT_AV*) h264->pSystemData;
	
	if (!sys)
		return;
	
	CVPixelBufferLockBaseAddress(imageBuffer, 0);
	
	h264->width = CVPixelBufferGetWidth(imageBuffer);
	h264->height = CVPixelBufferGetHeight(imageBuffer);
	
	BYTE* baseAddr = (BYTE*) CVPixelBufferGetBaseAddress(imageBuffer);
	
	if (!baseAddr)
		return;
	
	CVPlanarPixelBufferInfo_YCbCrPlanar* bufferInfo = (CVPlanarPixelBufferInfo_YCbCrPlanar*) baseAddr;
	planes.componentInfoY.offset = _byteswap_ulong(bufferInfo->componentInfoY.offset);
	planes.componentInfoY.rowBytes = _byteswap_ulong(bufferInfo->componentInfoY.rowBytes);
	planes.componentInfoCb.offset = _byteswap_ulong(bufferInfo->componentInfoCb.offset);
	planes.componentInfoCb.rowBytes = _byteswap_ulong(bufferInfo->componentInfoCb.rowBytes);
	planes.componentInfoCr.offset = _byteswap_ulong(bufferInfo->componentInfoCr.offset);
	planes.componentInfoCr.rowBytes = _byteswap_ulong(bufferInfo->componentInfoCr.rowBytes);
	
	h264->iStride[0] = planes.componentInfoY.rowBytes;
	h264->iStride[1] = planes.componentInfoCb.rowBytes;
	h264->iStride[2] = planes.componentInfoCr.rowBytes;
	
	UINT32 pic_size = (h264->iStride[0] * h264->height) +
		(h264->iStride[1] * (h264->height / 2)) + (h264->iStride[2] * (h264->height / 2));
	
	if (pic_size > sys->pic_size)
	{
		_aligned_free(sys->pic_data);
		sys->pic_data = _aligned_malloc(pic_size, 16);
		sys->pic_size = pic_size;
	}
	
	pDst = sys->pic_data;
	
	h264->pYUVData[0] = pDst;
	pSrc = &baseAddr[planes.componentInfoY.offset];
	CopyMemory(pDst, pSrc, h264->iStride[0] * h264->height);
	pDst += h264->iStride[0] * h264->height;
	
	h264->pYUVData[1] = pDst;
	pSrc = &baseAddr[planes.componentInfoCb.offset];
	CopyMemory(pDst, pSrc, h264->iStride[1] * (h264->height / 2));
	pDst += h264->iStride[1] * (h264->height / 2);
	
	h264->pYUVData[2] = pDst;
	pSrc = &baseAddr[planes.componentInfoCr.offset];
	CopyMemory(pDst, pSrc, h264->iStride[2] * (h264->height / 2));
	pDst += h264->iStride[2] * (h264->height / 2);
	
	CVPixelBufferUnlockBaseAddress(imageBuffer, 0);
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
	
	p[0] = 0x01; /* avc version */
	p[1] = sps->profile_idc; /* avc profile */
	p[2] = ((sps->constraint_set0_flag << 7) | (sps->constraint_set1_flag << 6) | (sps->constraint_set2_flag << 5) | /* avc compatibility */
		(sps->constraint_set3_flag << 4) | (sps->constraint_set4_flag << 3) | (sps->constraint_set5_flag << 2) | sps->reserved_zero_2bits);
	p[3] = sps->level_idc; /* avc level */
	p[4] = 0xFC | 0x3; /* 6 upper bits reserved, 2 lower bits NALULengthMinusOne */
	p[5] = 0xE0 | 0x1; /* 3 upper bits reserved, 5 lower bits number of SPS NALUs */
	p += 6;
	p[0] = (sys->sps_size >> 8) & 0xFF; /* 16-bit big-endian SPS size */
	p[1] = (sys->sps_size) & 0xFF;
	p += 2;
	CopyMemory(p, sys->sps_data, sys->sps_size); /* SPS data */
	p += sys->sps_size;
	p[0] = 0x01; /* number of PPS NALUs */
	p++;
	p[0] = (sys->pps_size >> 8) & 0xFF; /* 16-bit big-endian PPS size */
	p[1] = (sys->pps_size) & 0xFF;
	p += 2;
	CopyMemory(p, sys->pps_data, sys->pps_size); /* PPS data */
	p += sys->pps_size;
	
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
						sys->pic_width, sys->pic_height, (CFDictionaryRef) extensionDict, &sys->formatDescription);

	CFRelease(extensionDict);
	CFRelease(atomsDict);
	
	if (status != noErr)
	{
		WLog_ERR(TAG, "CMVideoFormatDescriptionCreate() failure: %d", status);
		return -1;
	}
	
	VTDecompressionOutputCallbackRecord outputCallback = { av_output_callback, h264 };
	
	NSDictionary* pixelBufferAttributes = @{(NSString*)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_420YpCbCr8PlanarFullRange)};
	
	status = VTDecompressionSessionCreate(kCFAllocatorDefault, sys->formatDescription, NULL,
					      (CFDictionaryRef) pixelBufferAttributes, &outputCallback, &sys->session);
	
	if (status != noErr)
	{
		WLog_ERR(TAG, "VTDecompressionSessionCreate() failure: %d", status);
		return -1;
	}
	
	return 1;
}

static int av_decompress(H264_CONTEXT* h264, BYTE* pSrcData, UINT32 SrcSize)
{
	BYTE* p;
	int f_size = 0;
	int f_offset = 0;
	OSStatus status;
	int nal_unit_index;
	int nal_unit_count;
	int f_nal_unit_index = 0;
	int f_nal_unit_count = 0;
	struct h264_byte_stream_nal_unit* nal;
	struct h264_byte_stream_nal_unit* nal_units = NULL;
	struct h264_byte_stream_nal_unit* f_nal_units = NULL;
	H264_CONTEXT_AV* sys = (H264_CONTEXT_AV*) h264->pSystemData;
	
	if (!sys)
		return -1;
	
	nal_unit_count = h264_parse_nal_units(h264, pSrcData, SrcSize, &nal_units);
	
	if ((nal_unit_count < 0) || !nal_units)
		return -1;
	
	f_nal_units = (struct h264_byte_stream_nal_unit*) calloc(nal_unit_count, sizeof(struct h264_byte_stream_nal_unit));
	
	if (!f_nal_units)
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
			
			sys->pic_width = ((sps->pic_width_in_mbs_minus1 + 1) * 16) -
				(sps->frame_crop_left_offset * 2) - (sps->frame_crop_right_offset * 2);
			
			sys->pic_height = ((2 - sps->frame_mbs_only_flag) * (sps->pic_height_in_map_units_minus1 + 1) * 16) -
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
			
			if (!sys->avcc_data)
			{
				if (av_create_format_description(h264) < 0)
				{
					fprintf(stderr, "av_create_format_description_failure\n");
					return -1;
				}
			}
		}
		else
		{
			CopyMemory(&f_nal_units[f_nal_unit_index], nal, sizeof(struct h264_byte_stream_nal_unit));
			f_size += (4 + nal->unit_size);
			f_nal_unit_index++;
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
		
		//fprintf(stderr, "[%02d] size: %d type: %d %s\n",
		//	nal_unit_index, nal->unit_size, nal->unit_type, h264_get_nal_unit_name(nal->unit_type));
	}
	
	f_nal_unit_count = f_nal_unit_index;
	
	if (!sys->session)
	{
		WLog_ERR(TAG, "invalid VTDecompressionSessionRef");
		return -1;
	}
	
	status = CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault, NULL, f_size,
						    kCFAllocatorDefault, NULL, 0, f_size, kCMBlockBufferAssureMemoryNowFlag, &sys->blockBuffer);
	
	if (status != noErr)
	{
		WLog_ERR(TAG, "CMBlockBufferCreateWithMemoryBlock() failure: %d", status);
		return -1;
	}
	
	for (f_nal_unit_index = 0; f_nal_unit_index < f_nal_unit_count; f_nal_unit_index++)
	{
		nal = &f_nal_units[f_nal_unit_index];
		
		p = nal->header_data - 4;
		
		if (p >= pSrcData)
		{
			status = CMBlockBufferReplaceDataBytes(p, sys->blockBuffer, f_offset, nal->unit_size + 4);
		
			if (status != noErr)
			{
				WLog_ERR(TAG, "CMBlockBufferReplaceDataBytes() failure: %d", status);
				return -1;
			}
			
			f_offset += nal->unit_size + 4;
		}
	}
	
	status = CMSampleBufferCreate(kCFAllocatorDefault, sys->blockBuffer, false, NULL, NULL,
				      sys->formatDescription, 1, 0, NULL, 0, NULL, &sys->sampleBuffer);
	
	if (status != noErr)
	{
		WLog_ERR(TAG, "CMSampleBufferCreate() failure: %d", status);
		return -1;
	}
	
	status = VTDecompressionSessionDecodeFrame(sys->session, sys->sampleBuffer, kVTDecodeFrame_EnableAsynchronousDecompression, NULL, NULL);
	
	if (status != noErr)
	{
		WLog_ERR(TAG, "VTDecompressionSessionDecodeFrame() failure: %d", status);
		return -1;
	}
	
	status = VTDecompressionSessionWaitForAsynchronousFrames(sys->session);
	
	if (status != noErr)
	{
		WLog_ERR(TAG, "VTDecompressionSessionWaitForAsynchronousFrames() failure: %d", status);
		return -1;
	}
	
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
	
	free(f_nal_units);
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
		
		if (sys->avcc_data)
		{
			free(sys->avcc_data);
			sys->avcc_data = NULL;
		}
		
		if (sys->pic_data)
		{
			_aligned_free(sys->pic_data);
			sys->pic_data = NULL;
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
