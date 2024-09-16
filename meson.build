project('ccsds', ['c'], default_options: [
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

ccsds_src = files([
    'src/rs/rs_encode.c',
    'src/rs/rs_decode.c',
    'src/ccsds.c',
    'src/ccsds_randomize.c',
    'src/crypto/crypto.c',
    'src/crypto/crypto_param.c',
    'src/crypto/tweetnacl.c',
])

ccsds_inc = include_directories('src')
api = include_directories('include')

ccsds_lib = library('ccsds',
	sources: [ccsds_src],
	include_directories : [ccsds_inc, api],
	dependencies : [csp_dep, param_dep],
	install : true
)
pkg = import('pkgconfig')
pkg.generate(ccsds_lib, filebase: 'ccsds')

ccsds_dep = declare_dependency(include_directories : api, link_with : ccsds_lib, dependencies: [csp_dep, param_dep])

if not meson.is_subproject()
    subdir('tests')
endif