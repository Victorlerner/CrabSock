// Frontend wrapper around Tauri v2 updater plugin.
// Keeps Vue components decoupled from the plugin API and makes "web mode" safe.

import { check as pluginCheck } from '@tauri-apps/plugin-updater'

function isTauriRuntime(): boolean {
  // Tauri v2 exposes internal bridge on window.__TAURI_INTERNALS__
  return typeof window !== 'undefined' && !!(window as any).__TAURI_INTERNALS__
}

export async function check() {
  if (!isTauriRuntime()) return null

  try {
    return await pluginCheck()
  } catch {
    // If updater isn't available (e.g. dev/web context) treat as "no update".
    return null
  }
}


