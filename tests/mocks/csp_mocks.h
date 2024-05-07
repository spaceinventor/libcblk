#pragma once

extern "C"
{
#include <csp/csp.h>
}

#include "modulemock.h"

namespace EmbeddedCUnitTest {

class CSPMock : public ModuleMock
{
public:
    MOCK_METHOD1( csp_iflist_add, int(csp_iface_t * ifc) );
    MOCK_METHOD1( csp_clock_get_time, void(csp_timestamp_t * time) );
    //MOCK_METHOD1( csp_id_prepend, void(csp_packet_t * packet) );
    //MOCK_METHOD1( csp_id_strip, int(csp_packet_t * packet) );
    //MOCK_METHOD1( csp_id_setup_rx, int(csp_packet_t * packet) );
    MOCK_METHOD0( csp_get_conf, const csp_conf_t * (void) );
    MOCK_METHOD0( csp_get_ms, uint32_t(void) );
    //MOCK_METHOD1( csp_buffer_free, void(void *buffer) );
    //MOCK_METHOD0( csp_buffer_remaining, int(void) );
    //MOCK_METHOD1( csp_buffer_get, csp_packet_t * (size_t unused) );
    MOCK_METHOD3( csp_qfifo_write, void(csp_packet_t * packet, csp_iface_t * iface, void * pxTaskWoken) );
};

}
