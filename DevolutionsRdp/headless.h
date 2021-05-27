#ifndef CS_HEADLESS_H_
#define CS_HEADLESS_H_

#include <freerdp/api.h>

FREERDP_API void* csharp_create_shared_buffer(char* name, int size);
#ifdef _WIN32
FREERDP_API void csharp_destroy_shared_buffer(void* hMapFile);
#else
FREERDP_API void csharp_destroy_shared_buffer(char* name);
#endif

#endif /* CS_HEADLESS_H_ */