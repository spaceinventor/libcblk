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
    mod = import('unstable-external_project')

    configure_opts = [
        '--enable-minimal',
        '--disable-ssp',
        '--disable-pie',
        '--enable-static',
        '--disable-shared',
        '--without-pthreads',
        '--prefix=@PREFIX@',
        '--libdir=@PREFIX@/@LIBDIR@',
        '--includedir=@PREFIX@/@INCLUDEDIR@',
    ]

    # we only support cross compiling to arm-none-eabi targets
    if meson.is_cross_build() == true
        sodium_env = environment()
        target_c_args = get_option('c_args')

        c_flags_str = '-O3 '
        foreach arg : target_c_args
            c_flags_str += arg + ' '
        endforeach

        sodium_env.set('CFLAGS', c_flags_str)
        sodium_env.set('LDFLAGS', '-specs=nosys.specs')

        cross_configure_opt = [
            '--host=arm-none-eabi',
        ]
    endif

    libsodium_proj = mod.add_project('src/crypto/sodium/configure',
        configure_options : configure_opts,
        verbose : false,
        cross_configure_options : cross_configure_opt,
        env : sodium_env,
    )

    sodium_dep = libsodium_proj.dependency('sodium')

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
