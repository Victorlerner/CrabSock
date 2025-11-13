<script setup lang="ts">
import { onMounted, ref, computed, watch } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()
const osPlatform = ref<'windows' | 'linux' | 'macos' | 'unknown'>('unknown')
const selected = ref<'systemproxy' | 'tun'>(store.routingMode)

function detectPlatform(): 'windows' | 'linux' | 'macos' | 'unknown' {
  const ua = navigator.userAgent.toLowerCase()
  if (ua.includes('windows')) return 'windows'
  if (ua.includes('mac os') || ua.includes('macintosh')) return 'macos'
  if (ua.includes('linux')) return 'linux'
  return 'unknown'
}

const options = computed(() => {
  if (osPlatform.value === 'macos') {
    return [ { label: 'System Proxy', value: 'systemproxy' as const }, { label: 'TUN (Kernel)', value: 'tun' as const } ]
  }
  if (osPlatform.value === 'linux') {
    return [ { label: 'TUN (Kernel)', value: 'tun' as const } ]
  }
  if (osPlatform.value === 'windows') {
    return [ { label: 'System Proxy', value: 'systemproxy' as const }, { label: 'TUN (Kernel)', value: 'tun' as const } ]
  }
  // Unknown: expose both to allow testing
  return [ { label: 'System Proxy', value: 'systemproxy' as const }, { label: 'TUN (Kernel)', value: 'tun' as const } ]
})

async function init() {
  osPlatform.value = detectPlatform()
  selected.value = store.routingMode
  // Keep local select in sync with store updates (e.g., after relaunch/elevation)
  watch(() => store.routingMode, (v) => { selected.value = v })
}

async function onChange() {
  if (osPlatform.value === 'windows' && selected.value === 'tun') {
    try {
      // Persist desired mode first so relaunched admin instance reads it
      await store.setRoutingMode('tun')

      const ok = await (await import('@tauri-apps/api/core')).invoke<boolean>('ensure_admin_for_tun')
      if (!ok) {
        store.addLog('info', 'Elevation requested. Confirm UAC dialog; app will relaunch as admin.', 'frontend')
        // Terminate current process to avoid double instances; elevated one will start
        await (await import('@tauri-apps/api/core')).invoke('exit_app')
        return
      }
    } catch (e) {
      // Roll back to System Proxy if elevation failed/cancelled
      await store.setRoutingMode('systemproxy')
      selected.value = 'systemproxy'
      store.addLog('error', `Failed to request admin rights: ${e}`, 'frontend')
      return
    }
    return
  }
  await store.setRoutingMode(selected.value)
}

onMounted(init)
</script>

<template>
  <div class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700 p-4">
    <div class="flex items-center justify-between">
      <div>
        <div class="text-sm font-medium">Routing mode</div>
        <div class="text-xs text-gray-500 dark:text-gray-400">
          <span v-if="osPlatform==='macos'">macOS: System Proxy or TUN</span>
          <span v-else-if="osPlatform==='linux'">Linux: TUN only</span>
          <span v-else>Windows: System Proxy by default</span>
        </div>
      </div>
      <select
        class="px-3 py-2 rounded-md bg-white dark:bg-neutral-700 border border-gray-300 dark:border-neutral-600 text-sm"
        v-model="selected"
        @change="onChange"
      >
        <option v-for="opt in options" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
      </select>
    </div>
    <div class="mt-3 text-xs text-gray-600 dark:text-gray-400 space-y-1">
      <div><strong>TUN mode</strong>: Captures all traffic, including UDP. May interrupt ongoing calls (VoIP) when connecting or switching.</div>
      <div><strong>System Proxy</strong>: Best for quickly opening resources in apps that honor system proxy (browsers, Postman). Does not affect UDP traffic.</div>
    </div>
  </div>
</template>


