#ifndef SECURITY_BRIDGE_ABI_H
#define SECURITY_BRIDGE_ABI_H

#include <stddef.h>
#include <stdint.h>

enum {
    SECURITY_VALUE_NULL = 0,
    SECURITY_VALUE_BOOL = 1,
    SECURITY_VALUE_INTEGER = 2,
    SECURITY_VALUE_UNSIGNED = 3,
    SECURITY_VALUE_REAL = 4,
    SECURITY_VALUE_STRING = 5,
    SECURITY_VALUE_DATA = 6,
    SECURITY_VALUE_DATE = 7,
    SECURITY_VALUE_URL = 8,
    SECURITY_VALUE_ARRAY = 9,
    SECURITY_VALUE_OBJECT = 10
};

typedef struct SecurityBridgeValue SecurityBridgeValue;
typedef struct SecurityBridgeEntry SecurityBridgeEntry;

typedef struct {
    const uint8_t *data;
    size_t length;
} SecurityBridgeBuffer;

struct SecurityBridgeValue {
    uint32_t tag;
    uint32_t reserved;
    int64_t integer;
    uint64_t unsigned_integer;
    double real;
    const uint8_t *bytes;
    size_t length;
    const SecurityBridgeValue *values;
    const SecurityBridgeEntry *entries;
};

struct SecurityBridgeEntry {
    SecurityBridgeBuffer key;
    SecurityBridgeValue value;
};

const SecurityBridgeValue *security_value_get(void *handle);
void security_release_handle(void *handle);

#endif
