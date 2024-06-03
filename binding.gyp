{
  'variables': {
    'openssl_fips' : '' 
  },
  "targets": [
    {
      "target_name": "bindings",
      'defines': [
        'NAPI_CPP_EXCEPTIONS=1',
        'EDHOC_KID_LEN=4',
        'EDHOC_MAX_CSUITES_LEN=9',
        'EDHOC_MAX_CID_LEN=7',
        'EDHOC_MAX_ECC_KEY_LEN=56',
        'EDHOC_MAX_MAC_LEN=64',
        'EDHOC_MAX_NR_OF_EAD_TOKENS=10',
        'EDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN=5',
        'EDHOC_CRED_KEY_ID_LEN=8',
        'EDHOC_CRED_X509_HASH_ALG_LEN=1',
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
            '_Static_assert=static_assert'
          ],
          'msvs_settings': {
            'VCCLCompilerTool': {
              'AdditionalOptions': [ '-std:c++20', ],
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
