// Frontend wrapper around Tauri v2 updater.
// Keeps Vue components decoupled from the backend implementation.

import { invoke } from '@tauri-apps/api/core'
import { isTauri } from '@tauri-apps/api/core'

export interface UpdateInfo {
  available: boolean
  version?: string
  current_version: string
  body?: string
  date?: string
}

export async function check(): Promise<UpdateInfo | null> {
  // In pure web mode the updater is unavailable.
  if (typeof window === 'undefined' || !isTauri()) return null

  try {
    const result = await invoke<UpdateInfo>('check_for_updates')
    console.log('[UPDATER] Backend check result:', result)
    return result
  } catch (error) {
    console.error('[UPDATER] Backend check failed:', error)
    throw error
  }
}

export async function downloadAndInstall(): Promise<void> {
  if (typeof window === 'undefined' || !isTauri()) {
    throw new Error('Not in Tauri environment')
  }

  try {
    console.log('[UPDATER] Starting download and install...')
    await invoke('download_and_install_update')
    console.log('[UPDATER] Download and install completed')
  } catch (error) {
    console.error('[UPDATER] Download/install failed:', error)
    throw error
  }
}


