#pragma once

#include "modulemock.h"

#include <gtest/gtest.h>
#include <exception>
#include <memory>


namespace EmbeddedCUnitTest {

extern std::unique_ptr<ModuleMockBase> moduleTestMocks;

template<typename T>
struct ModuleTest : public ::testing::Test
{
    ModuleTest()
    {
        moduleTestMocks.reset(new T);
    }

    virtual ~ModuleTest()
    {
        moduleTestMocks.reset();
    }
};

template<typename T>
static T& GetMock()
{
    auto ptr = dynamic_cast<T*>(moduleTestMocks.get());
    if (ptr == nullptr)
    {
        auto err = "The test does not provide mock of \"" + std::string(typeid(T).name()) + "\"";
        throw std::runtime_error(err.c_str());
    }
    return *ptr;
}

}
