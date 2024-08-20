#pragma once

#include <stdint.h>

class Observer {
public:
    virtual void update(uint16_t type) = 0;
    virtual ~Observer() = default;
};
