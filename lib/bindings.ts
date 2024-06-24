import nodeGypBuild from 'node-gyp-build'
import { EDHOC, EdhocCredentialManager, EdhocCryptoManager } from '@/edhoc'
import { join } from 'path'

export interface NodeGypBinding {
    EDHOC: EDHOC
    EdhocCryptoManager: EdhocCryptoManager
    EdhocCredentialManager: EdhocCredentialManager
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const binding = nodeGypBuild(join(__dirname, '../')) as NodeGypBinding

exports.EDHOC = binding.EDHOC
exports.EdhocCryptoManager = binding.EdhocCryptoManager
exports.EdhocCredentialManager = binding.EdhocCredentialManager