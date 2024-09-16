add_languages('cpp')

gtest_dep = dependency('gtest', main : true)
gtest_main_dep = dependency('gtest_main')
gmock_dep = dependency('gmock') 

test_sources = [
    'ccsds_tests.cpp',
    'mocks/mocks.cpp',
    'framework/modulemock.cpp',
    'framework/moduletest.cpp',
    'framework/vmem_file.c',
]

test_tests = executable(
    'ccsds_tests',
    [test_sources],
    include_directories: ['mocks', 'framework', '..',],
    dependencies: [gtest_dep, gtest_main_dep, gmock_dep, ccsds_dep,],  
)

test('ccsds_tests', test_tests)