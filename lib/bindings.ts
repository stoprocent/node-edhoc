import nodeGypBuild from 'node-gyp-build'
import { EDHOC } from './edhoc'
import { join } from 'path'

export interface NodeGypBinding {
    EDHOC: EDHOC
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const binding = nodeGypBuild(join(__dirname, '../')) as NodeGypBinding

exports.EDHOC = binding.EDHOC;
