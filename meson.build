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
    'src/csp_if_cblk.c',
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
