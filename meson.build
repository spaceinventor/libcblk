project('ccsds', 'c')

csp_dep = dependency('csp', fallback : ['csp', 'csp_dep'], required: false).partial_dependency(links: false, includes: true)
param_dep = dependency('param', fallback: ['param', 'param_dep'], required: false).partial_dependency(links: false, includes: true)

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

ccsds_lib = static_library('ccsds',
	sources: [ccsds_src],
	include_directories : ccsds_inc,
	dependencies : [csp_dep, param_dep],
	install : false
)

ccsds_dep = declare_dependency(include_directories : ccsds_inc, link_with : ccsds_lib)
