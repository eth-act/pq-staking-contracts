// Copy the exported contract bytecode into the site so the in-browser EVM runs exactly the
// bytes a release ships. Run via `npm run sync-contracts` (also runs before dev and build).
import { copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const source = resolve(here, '../../contracts/dist/bytecode.json')
const target = resolve(here, '../src/generated/bytecode.json')

if (!existsSync(source)) {
  console.error(`missing ${source}; run contracts/scripts/export-bytecode.sh`)
  process.exit(1)
}
mkdirSync(dirname(target), { recursive: true })
copyFileSync(source, target)
console.error(`synced ${target}`)
