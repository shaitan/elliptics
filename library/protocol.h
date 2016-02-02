#ifndef __DNET_PROTOCOL_HPP
#define __DNET_PROTOCOL_HPP

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#ifdef __cplusplus
extern "C" {
#endif

int dnet_convert_io(dnet_io_control *ctl);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_PROTOCOL_HPP */
