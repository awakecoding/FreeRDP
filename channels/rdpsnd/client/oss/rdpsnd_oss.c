/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Audio Output Virtual Channel
 *
 * Copyright (c) 2015 Rozhuk Ivan <rozhuk.im@gmail.com>
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
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

#include <freerdp/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/string.h>
#include <winpr/cmdline.h>
#include <winpr/sysinfo.h>
#include <winpr/collections.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>
#include <oss-includes.h>
#include <sys/ioctl.h>

#include <freerdp/types.h>
#include <freerdp/settings.h>
#include <freerdp/channels/log.h>

#include "rdpsnd_main.h"

typedef struct
{
	rdpsndDevicePlugin device;

	int pcm_handle;
	int mixer_handle;
	int dev_unit;

	int supported_formats;

	UINT32 latency;
	AUDIO_FORMAT format;
} rdpsndOssPlugin;

#define OSS_LOG_ERR(_text, _error)                                        \
	do                                                                    \
	{                                                                     \
		if ((_error) != 0)                                                \
		{                                                                 \
			char ebuffer[256] = { 0 };                                    \
			WLog_ERR(TAG, "%s: %i - %s", (_text), (_error),               \
			         winpr_strerror((_error), ebuffer, sizeof(ebuffer))); \
		}                                                                 \
	} while (0)

static int rdpsnd_oss_get_format(const AUDIO_FORMAT* format)
{
	switch (format->wFormatTag)
	{
		case WAVE_FORMAT_PCM:
			switch (format->wBitsPerSample)
			{
				case 8:
					return AFMT_S8;

				case 16:
					return AFMT_S16_LE;
				default:
					break;
			}

			break;
		default:
			break;
	}

	return 0;
}

static BOOL rdpsnd_oss_format_supported(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format)
{
	int req_fmt = 0;
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)device;

	if (device == NULL || format == NULL)
		return FALSE;

	switch (format->wFormatTag)
	{
		case WAVE_FORMAT_PCM:
			if (format->cbSize != 0 || format->nSamplesPerSec > 48000 ||
			    (format->wBitsPerSample != 8 && format->wBitsPerSample != 16) ||
			    (format->nChannels != 1 && format->nChannels != 2))
				return FALSE;

			break;

		default:
			return FALSE;
	}

	req_fmt = rdpsnd_oss_get_format(format);

	/* Check really supported formats by dev. */
	if (oss->pcm_handle != -1)
	{
		if ((req_fmt & oss->supported_formats) == 0)
			return FALSE;
	}
	else
	{
		if (req_fmt == 0)
			return FALSE;
	}

	return TRUE;
}

static BOOL rdpsnd_oss_set_format(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format,
                                  UINT32 latency)
{
	int tmp = 0;
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)device;

	if (device == NULL || oss->pcm_handle == -1 || format == NULL)
		return FALSE;

	oss->latency = latency;
	CopyMemory(&(oss->format), format, sizeof(AUDIO_FORMAT));
	tmp = rdpsnd_oss_get_format(format);

	if (ioctl(oss->pcm_handle, SNDCTL_DSP_SETFMT, &tmp) == -1)
	{
		OSS_LOG_ERR("SNDCTL_DSP_SETFMT failed", errno);
		return FALSE;
	}

	tmp = format->nChannels;

	if (ioctl(oss->pcm_handle, SNDCTL_DSP_CHANNELS, &tmp) == -1)
	{
		OSS_LOG_ERR("SNDCTL_DSP_CHANNELS failed", errno);
		return FALSE;
	}

	tmp = (int)format->nSamplesPerSec;

	if (ioctl(oss->pcm_handle, SNDCTL_DSP_SPEED, &tmp) == -1)
	{
		OSS_LOG_ERR("SNDCTL_DSP_SPEED failed", errno);
		return FALSE;
	}

	tmp = format->nBlockAlign;

	if (ioctl(oss->pcm_handle, SNDCTL_DSP_SETFRAGMENT, &tmp) == -1)
	{
		OSS_LOG_ERR("SNDCTL_DSP_SETFRAGMENT failed", errno);
		return FALSE;
	}

	return TRUE;
}

static void rdpsnd_oss_open_mixer(rdpsndOssPlugin* oss)
{
	int devmask = 0;
	char mixer_name[PATH_MAX] = "/dev/mixer";

	if (oss->mixer_handle != -1)
		return;

	if (oss->dev_unit != -1)
		(void)sprintf_s(mixer_name, PATH_MAX - 1, "/dev/mixer%i", oss->dev_unit);

	if ((oss->mixer_handle = open(mixer_name, O_RDWR)) < 0)
	{
		OSS_LOG_ERR("mixer open failed", errno);
		oss->mixer_handle = -1;
		return;
	}

	if (ioctl(oss->mixer_handle, SOUND_MIXER_READ_DEVMASK, &devmask) == -1)
	{
		OSS_LOG_ERR("SOUND_MIXER_READ_DEVMASK failed", errno);
		close(oss->mixer_handle);
		oss->mixer_handle = -1;
		return;
	}
}

static BOOL rdpsnd_oss_open(rdpsndDevicePlugin* device, const AUDIO_FORMAT* format, UINT32 latency)
{
	char dev_name[PATH_MAX] = "/dev/dsp";
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)device;

	if (device == NULL || oss->pcm_handle != -1)
		return TRUE;

	if (oss->dev_unit != -1)
		(void)sprintf_s(dev_name, PATH_MAX - 1, "/dev/dsp%i", oss->dev_unit);

	WLog_INFO(TAG, "open: %s", dev_name);

	if ((oss->pcm_handle = open(dev_name, O_WRONLY)) < 0)
	{
		OSS_LOG_ERR("sound dev open failed", errno);
		oss->pcm_handle = -1;
		return FALSE;
	}

	if (ioctl(oss->pcm_handle, SNDCTL_DSP_GETFMTS, &oss->supported_formats) == -1)
	{
		OSS_LOG_ERR("SNDCTL_DSP_GETFMTS failed", errno);
		close(oss->pcm_handle);
		oss->pcm_handle = -1;
		return FALSE;
	}

	rdpsnd_oss_set_format(device, format, latency);
	rdpsnd_oss_open_mixer(oss);
	return TRUE;
}

static void rdpsnd_oss_close(rdpsndDevicePlugin* device)
{
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)device;

	if (device == NULL)
		return;

	if (oss->pcm_handle != -1)
	{
		WLog_INFO(TAG, "close: dsp");
		close(oss->pcm_handle);
		oss->pcm_handle = -1;
	}

	if (oss->mixer_handle != -1)
	{
		WLog_INFO(TAG, "close: mixer");
		close(oss->mixer_handle);
		oss->mixer_handle = -1;
	}
}

static void rdpsnd_oss_free(rdpsndDevicePlugin* device)
{
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)device;

	if (device == NULL)
		return;

	rdpsnd_oss_close(device);
	free(oss);
}

static UINT32 rdpsnd_oss_get_volume(rdpsndDevicePlugin* device)
{
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)device;
	WINPR_ASSERT(oss);
	int vol = 0;

	/* On error return 50% volume. */
	UINT32 dwVolumeLeft = ((50 * 0xFFFF) / 100);  /* 50% */
	UINT32 dwVolumeRight = ((50 * 0xFFFF) / 100); /* 50% */
	UINT32 dwVolume = ((dwVolumeLeft << 16) | dwVolumeRight);

	if (device == NULL || oss->mixer_handle == -1)
		return dwVolume;

	if (ioctl(oss->mixer_handle, MIXER_READ(SOUND_MIXER_VOLUME), &vol) == -1)
	{
		OSS_LOG_ERR("MIXER_READ", errno);
		return dwVolume;
	}

	dwVolumeLeft = (((vol & 0x7f) * 0xFFFF) / 100);
	dwVolumeRight = ((((vol >> 8) & 0x7f) * 0xFFFF) / 100);
	dwVolume = ((dwVolumeLeft << 16) | dwVolumeRight);
	return dwVolume;
}

static BOOL rdpsnd_oss_set_volume(rdpsndDevicePlugin* device, UINT32 value)
{
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)device;
	WINPR_ASSERT(oss);

	if (device == NULL || oss->mixer_handle == -1)
		return FALSE;

	unsigned left = (((value & 0xFFFF) * 100) / 0xFFFF);
	unsigned right = ((((value >> 16) & 0xFFFF) * 100) / 0xFFFF);

	left |= (right << 8);

	if (ioctl(oss->mixer_handle, MIXER_WRITE(SOUND_MIXER_VOLUME), &left) == -1)
	{
		OSS_LOG_ERR("WRITE_MIXER", errno);
		return FALSE;
	}

	return TRUE;
}

static UINT rdpsnd_oss_play(rdpsndDevicePlugin* device, const BYTE* data, size_t size)
{
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)device;

	if (device == NULL || oss->mixer_handle == -1)
		return 0;

	while (size > 0)
	{
		ssize_t status = write(oss->pcm_handle, data, size);

		if (status < 0)
		{
			OSS_LOG_ERR("write fail", errno);
			rdpsnd_oss_close(device);
			rdpsnd_oss_open(device, NULL, oss->latency);
			break;
		}

		data += status;

		if ((size_t)status <= size)
			size -= (size_t)status;
		else
			size = 0;
	}

	return 10; /* TODO: Get real latency in [ms] */
}

static int rdpsnd_oss_parse_addin_args(rdpsndDevicePlugin* device, const ADDIN_ARGV* args)
{
	int status = 0;
	char* str_num = NULL;
	char* eptr = NULL;
	DWORD flags = 0;
	const COMMAND_LINE_ARGUMENT_A* arg = NULL;
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)device;
	COMMAND_LINE_ARGUMENT_A rdpsnd_oss_args[] = { { "dev", COMMAND_LINE_VALUE_REQUIRED, "<device>",
		                                            NULL, NULL, -1, NULL, "device" },
		                                          { NULL, 0, NULL, NULL, NULL, -1, NULL, NULL } };
	flags =
	    COMMAND_LINE_SIGIL_NONE | COMMAND_LINE_SEPARATOR_COLON | COMMAND_LINE_IGN_UNKNOWN_KEYWORD;
	status =
	    CommandLineParseArgumentsA(args->argc, args->argv, rdpsnd_oss_args, flags, oss, NULL, NULL);

	if (status < 0)
		return status;

	arg = rdpsnd_oss_args;
	errno = 0;

	do
	{
		if (!(arg->Flags & COMMAND_LINE_VALUE_PRESENT))
			continue;

		CommandLineSwitchStart(arg) CommandLineSwitchCase(arg, "dev")
		{
			str_num = _strdup(arg->Value);

			if (!str_num)
				return ERROR_OUTOFMEMORY;

			{
				long val = strtol(str_num, &eptr, 10);

				if ((errno != 0) || (val < INT32_MIN) || (val > INT32_MAX))
				{
					free(str_num);
					return CHANNEL_RC_NULL_DATA;
				}

				oss->dev_unit = (int)val;
			}

			if (oss->dev_unit < 0 || *eptr != '\0')
				oss->dev_unit = -1;

			free(str_num);
		}
		CommandLineSwitchEnd(arg)
	} while ((arg = CommandLineFindNextArgumentA(arg)) != NULL);

	return status;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
FREERDP_ENTRY_POINT(UINT VCAPITYPE oss_freerdp_rdpsnd_client_subsystem_entry(
    PFREERDP_RDPSND_DEVICE_ENTRY_POINTS pEntryPoints))
{
	const ADDIN_ARGV* args = NULL;
	rdpsndOssPlugin* oss = (rdpsndOssPlugin*)calloc(1, sizeof(rdpsndOssPlugin));

	if (!oss)
		return CHANNEL_RC_NO_MEMORY;

	oss->device.Open = rdpsnd_oss_open;
	oss->device.FormatSupported = rdpsnd_oss_format_supported;
	oss->device.GetVolume = rdpsnd_oss_get_volume;
	oss->device.SetVolume = rdpsnd_oss_set_volume;
	oss->device.Play = rdpsnd_oss_play;
	oss->device.Close = rdpsnd_oss_close;
	oss->device.Free = rdpsnd_oss_free;
	oss->pcm_handle = -1;
	oss->mixer_handle = -1;
	oss->dev_unit = -1;
	args = pEntryPoints->args;
	if (rdpsnd_oss_parse_addin_args(&oss->device, args) < 0)
	{
		free(oss);
		return ERROR_INVALID_PARAMETER;
	}
	pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, (rdpsndDevicePlugin*)oss);
	return CHANNEL_RC_OK;
}
