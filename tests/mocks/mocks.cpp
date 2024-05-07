#include <stdarg.h>
#include "mocks.h"

using namespace EmbeddedCUnitTest;

extern "C"
{

int csp_iflist_add(csp_iface_t * ifc)
{
    return GetMock<CSPMock>().csp_iflist_add(ifc);
}

void csp_clock_get_time(csp_timestamp_t * time)
{
    GetMock<CSPMock>().csp_clock_get_time(time);
}

#if 0
void csp_id_prepend(csp_packet_t * packet)
{
    GetMock<CSPMock>().csp_id_prepend(packet);
}

int csp_id_strip(csp_packet_t * packet)
{
    return GetMock<CSPMock>().csp_id_strip(packet);
}

int csp_id_setup_rx(csp_packet_t * packet)
{
    return GetMock<CSPMock>().csp_id_setup_rx(packet);
}
#endif

const csp_conf_t * csp_get_conf(void)
{
    return GetMock<CSPMock>().csp_get_conf();
}

uint32_t csp_get_ms(void)
{
    return GetMock<CSPMock>().csp_get_ms();
}

#if 0
void csp_buffer_free(void *buffer)
{
    GetMock<CSPMock>().csp_buffer_free(buffer);
}

int csp_buffer_remaining(void)
{
    return GetMock<CSPMock>().csp_buffer_remaining();
}

csp_packet_t * csp_buffer_get(size_t unused)
{
    return GetMock<CSPMock>().csp_buffer_get(unused);
}
#endif
void csp_qfifo_write(csp_packet_t * packet, csp_iface_t * iface, void * pxTaskWoken)
{
    GetMock<CSPMock>().csp_qfifo_write(packet, iface, pxTaskWoken);
}

void csp_print_func(const char *fmt, ...)
{
    va_list arg;
    va_start(arg, fmt);

    char buffer[1024];
    vsnprintf(buffer, 1024, fmt, arg);

    printf("%s", buffer);

    va_end(arg);
}

}
