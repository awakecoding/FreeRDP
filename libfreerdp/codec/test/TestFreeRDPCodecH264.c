#include <winpr/crt.h>
#include <winpr/path.h>
#include <winpr/print.h>

#include <freerdp/codec/h264.h>

static char* TEST_H264_FILE = "/tmp/h264_rdp1/rdp_record_1024x768_24p.264";

int test_h264_bitstream_parse()
{
	FILE* fp;
	BYTE* data;
	UINT32 size;
	int status;

	if (!PathFileExistsA(TEST_H264_FILE))
		return 1;

	size = 8192;
	data = (BYTE*) malloc(size);

	if (!data)
		return -1;

	fp = fopen(TEST_H264_FILE, "r");

	if (!fp)
		return -1;

	fread(data, size, 1, fp);

	status = h264_parse_byte_stream(data, size);

	free(data);

	return 1;
}

int TestFreeRDPCodecH264(int argc, char** argv)
{
	test_h264_bitstream_parse();
	
	return 0;
}
