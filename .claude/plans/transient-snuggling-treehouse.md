# Plan: Remove Native C/C++ Module Artifacts

## Goal
Remove all C++, C, node-gyp, and native module related files from the repository, now that EDHOC is implemented in pure TypeScript.

## Directories to Delete

| Directory | Contents |
|-----------|----------|
| `src/` | 12 C++ source files (Binding.cpp, EdhocCryptoManager.cpp, etc.) |
| `include/` | 12 C++ header files |
| `build/` | node-gyp build artifacts (config.gypi) |
| `external/` | libedhoc git submodule (C library + mbedtls, zcbor, etc.) |

## Files to Delete

| File | Reason |
|------|--------|
| `.clang-format` | C/C++ code formatting config |
| `lib/node-gype-build.d.ts` | Type declaration for native module loader |
| `dist/bindings.js` | Compiled native binding loader |
| `dist/bindings.d.ts` | Type declaration for native bindings |
| `dist/bindings.d.ts.map` | Source map for above |

## Git Submodule Removal

- Deinit and remove `external/libedhoc` submodule
- Delete `.gitmodules` (only contains the one submodule)

## Files to Modify

### `.npmignore`
Remove lines referencing `external/` C/C++ files. Update to reflect pure TS package:
- Remove: `external/**/*`, `!external/**/*.c`, `!external/**/*.h`, `build`
- Add: `src` (if not already there for TS sources)

### `.github/workflows/build.yml`
Replace the native prebuild pipeline with a simple TS build + release:
- Remove `prebuild` job (matrix of OS/arch native builds)
- Simplify `release` job: checkout, npm ci, tsc, semantic-release
- Remove `submodules: recursive` from checkout steps
- Remove artifact upload/download steps

### `.github/workflows/test.yml`
Simplify for pure TS:
- Remove `submodules: recursive` from all checkout steps
- Remove "Remove __attribute__ for Windows" step
- Remove `npm run rebuild` step (replaced by `npm run build` via pretest)
- Keep lint, typescript, and test jobs

### `.vscode/tasks.json`
Remove the "npm: debug" task that references `node-gyp build --debug`.

## Verification

1. `npx tsc` compiles cleanly
2. `npx jest` — all 5 tests pass
3. `git status` shows only intended deletions/modifications
