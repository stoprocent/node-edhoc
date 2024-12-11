{
  'variables': {
    'openssl_fips' : '' 
  },
  "targets": [
    {
      "target_name": "bindings",
      'defines': [
        'NAPI_CPP_EXCEPTIONS=1',
        'CONFIG_LIBEDHOC_ENABLE=1',
        'CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES=9',
        'CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID=7',
        'CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY=56',
        'CONFIG_LIBEDHOC_MAX_LEN_OF_MAC=64',
        'CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS=10',
        'CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID=1',
        'CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN=5',
        'CONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG=1',
        'CONFIG_LIBEDHOC_KEY_ID_LEN=4',
        'ZCBOR_CANONICAL=1'
      ],
      "sources": [ 
        "<!@(node -p \"require('fs').readdirSync('external/libedhoc/library').map(f=>'external/libedhoc/library/'+f).join(' ')\")",
        "<!@(node -p \"require('fs').readdirSync('external/libedhoc/externals/zcbor/src').map(f=>'external/libedhoc/externals/zcbor/src/'+f).join(' ')\")",
        "<!@(node -p \"require('fs').readdirSync('external/libedhoc/backends/cbor/src').map(f=>'external/libedhoc/backends/cbor/src/'+f).join(' ')\")",
        "<!@(node -p \"require('fs').readdirSync('src').map(f=>'src/'+f).join(' ')\")"
      ],
      'include_dirs': [
        "<!@(node -p \"require('node-addon-api').include\")",
        "external/libedhoc/include",
        "external/libedhoc/externals/zcbor/include",
        "external/libedhoc/backends/cbor/include",
        "include"
      ],
      'dependencies': [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      'cflags!': [ '-fno-exceptions', '-std=c99' ],
      'cflags_cc!': [ '-fno-exceptions', '-std=c++20' ],
      'xcode_settings': {
        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
        'CLANG_CXX_LIBRARY': 'libc++',
        'CLANG_CXX_LANGUAGE_STANDARD': 'c++20',
        'MACOSX_DEPLOYMENT_TARGET': '12'
      },
      'conditions': [
        ['OS=="win"', {
          'defines': [
            '_Static_assert=static_assert',
            '__attribute__(x)='
          ],
          'msvs_settings': {
            'VCCLCompilerTool': {
              'AdditionalOptions': [ '-std:c++20', "/D__attribute__(x)="],
              'ExceptionHandling': 1
            }
          }
        }, { # OS != "win",
          'defines': [
            'restrict=__restrict'
          ],
        }]
      ],
    }
  ]
}
