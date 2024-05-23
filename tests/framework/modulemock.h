#pragma once

#include <gmock/gmock.h>


namespace EmbeddedCUnitTest {

struct ModuleMockBase
{
    virtual ~ModuleMockBase();
};

struct ReturnAfterHookSwitch
{
    ReturnAfterHookSwitch()
    {
        returnAfterHook = true;
    }

    bool ShouldReturnAfterHook()
    {
        return returnAfterHook;
    }

    bool returnAfterHook;
};

// 1. The ModuleMockBase inheritance must be virtual to allow storing mocks in the singleton.
// 2. The ReturnAfterHookSwitch inheritance must be non-virtual to allow different switch for every mock.
struct ModuleMock
    : public virtual ModuleMockBase
    , public ReturnAfterHookSwitch
{
};

}
