#include "SecurityBridgeABI.h"

_Static_assert(sizeof(SecurityBridgeBuffer) == 16, "buffer layout");
_Static_assert(sizeof(SecurityBridgeValue) == 64, "value layout");
_Static_assert(sizeof(SecurityBridgeEntry) == 80, "entry layout");
_Static_assert(offsetof(SecurityBridgeValue, integer) == 8, "integer layout");
_Static_assert(offsetof(SecurityBridgeValue, bytes) == 32, "bytes layout");
_Static_assert(offsetof(SecurityBridgeValue, entries) == 56, "entries layout");
