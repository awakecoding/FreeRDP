/**
 * WinPR: Windows Portable Runtime
 * Print Utils
 *
 * Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <winpr/crt.h>
#include <winpr/print.h>

#include "trio.h"

int winpr_HexDumpToBuffer(char* buffer, size_t count, BYTE* data, int length)
{
	BYTE* p = data;
	int i, line, offset = 0;
	int x = 0;

	x += sprintf_s(buffer, count, "     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F\n");

	while (offset < length)
	{
		x += sprintf_s(buffer+x, count-x, "%04x ", offset);

		line = length - offset;

		if (line > WINPR_HEXDUMP_LINE_LENGTH)
			line = WINPR_HEXDUMP_LINE_LENGTH;

		for (i = 0; i < line; i++)
			x += sprintf_s(buffer+x, count-x, "%02x ", p[i]);

		for (; i < WINPR_HEXDUMP_LINE_LENGTH; i++)
			x += sprintf_s(buffer+x, count-x, "   ");

		for (i = 0; i < line; i++)
			x += sprintf_s(buffer+x, count-x, "%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.');

		x += sprintf_s(buffer+x, count-x, "\n");

		offset += line;
		p += line;
	}

	return x;
}

void winpr_HexDumpf(BYTE* data, int length, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	winpr_HexDump(data, length);
}

void winpr_HexDump(BYTE* data, int length)
{
	BYTE* p = data;
	int i, line, offset = 0;

	while (offset < length)
	{
		fprintf(stderr, "%04x ", offset);

		line = length - offset;

		if (line > WINPR_HEXDUMP_LINE_LENGTH)
			line = WINPR_HEXDUMP_LINE_LENGTH;

		for (i = 0; i < line; i++)
			fprintf(stderr, "%02x ", p[i]);

		for (; i < WINPR_HEXDUMP_LINE_LENGTH; i++)
			fprintf(stderr, "   ");

		for (i = 0; i < line; i++)
			fprintf(stderr, "%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.');

		fprintf(stderr, "\n");

		offset += line;
		p += line;
	}
	fflush(stderr);
}

void winpr_CArrayDump(BYTE* data, int length, int width)
{
	BYTE* p = data;
	int i, line, offset = 0;

	while (offset < length)
	{
		line = length - offset;

		if (line > width)
			line = width;

		printf("\t\"");

		for (i = 0; i < line; i++)
			printf("\\x%02X", p[i]);

		printf("\"\n");

		offset += line;
		p += line;
	}

	printf("\n");
}

char* winpr_BinToHexString(BYTE* data, int length, BOOL space)
{
	int i;
	int n;
	char* p;
	int ln, hn;
	char bin2hex[] = "0123456789ABCDEF";

	n = space ? 3 : 2;

	p = (char*) malloc((length + 1) * n);

	for (i = 0; i < length; i++)
	{
		ln = data[i] & 0xF;
		hn = (data[i] >> 4) & 0xF;

		p[i * n] = bin2hex[hn];
		p[(i * n) + 1] = bin2hex[ln];

		if (space)
			p[(i * n) + 2] = ' ';
	}

	p[length * n] = '\0';

	return p;
}

int wvprintfx(const char *fmt, va_list args)
{
	return trio_vprintf(fmt, args);
}

int wprintfx(const char *fmt, ...)
{
	va_list args;
	int status;

	va_start(args, fmt);
	status = trio_vprintf(fmt, args);
	va_end(args);

	return status;
}

int wvsnprintfx(char *buffer, size_t bufferSize, const char* fmt, va_list args)
{
	return trio_vsnprintf(buffer, bufferSize, fmt, args);
}

int wprintfxToBuffer(char *buffer, size_t count, const char *fmt, ...)
{
	va_list args;
	int status;

	va_start(args, fmt);
	status = trio_snprintf(buffer, count, fmt, args);
	va_end(args);

	return status;
}

