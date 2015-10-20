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
	H264_CONTEXT* h264;

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

	h264 = h264_context_new(FALSE);

	status = h264_parse(h264, data, size);

	h264_context_free(h264);

	free(data);

	return 1;
}

int TestFreeRDPCodecH264(int argc, char** argv)
{
	test_h264_bitstream_parse();
	
	return 0;
}
