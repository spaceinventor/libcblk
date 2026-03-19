project('cblk', ['c', 'cpp'])

cblk_deps = []
cblk_args = []

if not meson.is_subproject()
    csp_dep = dependency('csp', fallback : ['csp', 'csp_dep'], required: true).partial_dependency(links: true, includes: true)
    param_dep = dependency('param', fallback: ['param', 'param_dep'], required: true).partial_dependency(links: true, includes: true)
else
    csp_dep = dependency('csp', fallback : ['csp', 'csp_dep'], required: true).partial_dependency(links: false, includes: true)
    param_dep = dependency('param', fallback: ['param', 'param_dep'], required: true).partial_dependency(links: false, includes: true)
endif

cblk_deps += [csp_dep, param_dep]

cblk_src = files([
    'src/csp_if_cblk.c',
    'src/crypto/crypto.c',
    'src/crypto/crypto_param.c',
])

nacl_impl = get_option('nacl_impl')

if nacl_impl == 'tweetnacl'
    cblk_src += 'src/crypto/tweetnacl.c'
    cblk_args += '-DUSE_TWEETNACL'
elif nacl_impl == 'sodium'
    if meson.is_cross_build()
        sodium_proj = subproject('sodium', required: true)
        sodium_dep = sodium_proj.get_variable('sodium_dep')
    else
        sodium_dep = dependency('libsodium', required: true)
    endif
    cblk_deps += sodium_dep
    cblk_args += '-DUSE_SODIUM'
endif

cblk_inc = include_directories('src')
api = include_directories('include')

cblk_lib = static_library('cblk',
	sources: [cblk_src],
	include_directories : [cblk_inc, api],
	dependencies : cblk_deps,
        c_args : cblk_args,
	install : false
)

cblk_dep = declare_dependency(
    include_directories : api,
    link_with : cblk_lib,
    dependencies: cblk_deps,
)
