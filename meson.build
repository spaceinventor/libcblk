project('cblk', ['c', 'cpp'], default_options: [
	'buildtype=debug', 
	'c_std=gnu11', 
	'b_lto=false',
    'b_lundef=false',
    'default_library=shared'])

if not meson.is_subproject()
    csp_dep = dependency('csp', fallback : ['csp', 'csp_dep'], required: true).partial_dependency(links: true, includes: true)
    param_dep = dependency('param', fallback: ['param', 'param_dep'], required: true).partial_dependency(links: true, includes: true)
else
    csp_dep = dependency('csp', fallback : ['csp', 'csp_dep'], required: true).partial_dependency(links: false, includes: true)
    param_dep = dependency('param', fallback: ['param', 'param_dep'], required: true).partial_dependency(links: false, includes: true)
endif

cblk_src = files([
    'src/rs/rs_encode.c',
    'src/rs/rs_decode.c',
    'src/csp_if_cblk.c',
    'src/ccsds_randomize.c',
    'src/crypto/crypto.c',
    'src/crypto/crypto_param.c',
    'src/crypto/tweetnacl.c',
])

cblk_inc = include_directories('src')
api = include_directories('include')

cblk_lib = static_library('cblk',
	sources: [cblk_src],
	include_directories : [cblk_inc, api],
	dependencies : [csp_dep, param_dep],
	install : false
)

cblk_dep = declare_dependency(include_directories : api, link_with : cblk_lib, dependencies: [csp_dep, param_dep])

if not meson.is_subproject()
    cmake = import('cmake')
    gtest_proj = cmake.subproject('gtest')
    gtest_dep = gtest_proj.get_variable('gtest_dep') 
    gtest_main_dep = gtest_proj.get_variable('gtest_main_dep') 
    gmock_dep = gtest_proj.get_variable('gmock_dep') 
    gtest_lib = static_library('gtest', install : false)
    gmock_lib = static_library('gmock', install: false) 
    subdir('tests')
endif