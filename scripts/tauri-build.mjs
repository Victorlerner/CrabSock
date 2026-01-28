import { spawnSync } from 'node:child_process'

// If TAURI_SIGNING_PRIVATE_KEY is not present, we fall back to a local config
// that disables updater artifact signing (`bundle.createUpdaterArtifacts=false`).
const hasSigningKey = !!process.env.TAURI_SIGNING_PRIVATE_KEY

const args = ['build']
if (!hasSigningKey) {
  args.push('--config', 'src-tauri/tauri.conf.local.json')
}

// Preserve the original parallelism flag from the previous npm script.
args.push('--', '-j', '8')

const res = spawnSync('tauri', args, {
  stdio: 'inherit',
  shell: true,
  env: process.env,
})

process.exit(res.status ?? 1)


