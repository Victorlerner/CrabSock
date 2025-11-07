<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()
const fileInput = ref<HTMLInputElement | null>(null)
const openvpnLogsCollapsed = ref(false)

const isConnected = computed(() => store.openvpnStatus === 'connected')
const isConnecting = computed(() => store.openvpnStatus === 'connecting')

function triggerFileDialog() {
  fileInput.value?.click()
}

async function onFileSelected(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  if (!/\.ovpn$/i.test(file.name)) {
    store.addLog('error', 'Please select a .ovpn file', 'frontend')
    return
  }
  await store.uploadOpenVpnConfig(file)
  if (fileInput.value) fileInput.value.value = ''
}

async function connect(name: string) {
  await store.connectOpenVpn(name)
}

async function disconnect() {
  await store.disconnectOpenVpn()
}

function confirmRemoveOpenVpn(name: string) {
  if (window.confirm('Are you sure you want to delete this configuration?')) {
    store.removeOpenVpnConfig(name)
  }
}

onMounted(() => {
  store.refreshOpenVpnConfigs()
})
</script>

<template>
  <section class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700 p-4">
    <div class="flex items-center justify-between gap-3 mb-3">
      <h2 class="text-lg font-semibold">OpenVPN</h2>
      <div class="flex items-center gap-2">
        <input ref="fileInput" type="file" accept=".ovpn" class="hidden" @change="onFileSelected" />
        <button class="px-3 py-1.5 rounded-md bg-blue-600 text-white hover:bg-blue-700" @click="triggerFileDialog">Upload .ovpn</button>
      </div>
    </div>

    <div class="space-y-2">
      <div v-if="store.openvpnConfigs.length === 0" class="text-sm text-gray-500">No .ovpn configs yet</div>
      <div v-for="c in store.openvpnConfigs" :key="c.name" class="flex items-center justify-between border border-gray-200/60 dark:border-neutral-700 rounded-lg p-2">
        <div class="truncate">
          <div class="font-medium truncate">{{ c.remote || c.display_name || c.name }}     <div
            v-if="store.openvpnActiveConfig === c.name && isConnecting"
            class="w-3 h-3 border-2 rounded-full animate-spin"
            :class="{
              'border-yellow-600 border-t-transparent': true
            }"
            aria-label="Connecting"
          /></div>
          <div class="text-xs text-gray-500 truncate">{{ c.display_name || c.path }}</div>
              <!-- inline spinner while connecting -->
          
        </div>
        <div class="flex items-center gap-2">
          <span class="text-xs px-2 py-0.5 rounded-full" :class="{
              'bg-green-100 text-green-700': isConnected && store.openvpnActiveConfig === c.name,
              'bg-yellow-100 text-yellow-700': isConnecting && store.openvpnActiveConfig === c.name,
              'bg-gray-100 text-gray-600': !(isConnected || isConnecting) || store.openvpnActiveConfig !== c.name
            }">
            {{ store.openvpnActiveConfig === c.name ? store.openvpnStatus : 'idle' }}
          </span>
      
          <button
            v-if="store.openvpnActiveConfig === c.name && isConnected"
            class="px-3 py-1.5 rounded-md bg-red-600 text-white hover:bg-red-700"
            @click="disconnect"
          >Disconnect</button>

          <button
            v-else-if="store.openvpnActiveConfig === c.name && isConnecting"
            class="px-3 py-1.5 rounded-md bg-orange-600 text-white hover:bg-orange-700"
            @click="disconnect"
          >Abort</button>

          <button
            v-else
            class="px-3 py-1.5 rounded-md bg-emerald-600 text-white hover:bg-emerald-700"
            :disabled="isConnecting"
            @click="connect(c.name)"
          >Connect</button>

          <button
            class="p-1.5 rounded-md hover:bg-red-100 dark:hover:bg-red-900/30"
            :disabled="store.openvpnActiveConfig === c.name && isConnecting"
            @click="confirmRemoveOpenVpn(c.name)"
            title="Remove config"
          >
            <svg class="w-4 h-4 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
            </svg>
          </button>
        </div>
      </div>
    </div>


    <div v-if="store.openvpnLogs.length && store.openvpnStatus !== 'disconnected'" class="mt-3">
      <div class="flex items-center justify-between mb-1">
        <div class="text-sm font-medium">OpenVPN Logs</div>
        <button
          class="p-1 rounded-md hover:bg-gray-200 dark:hover:bg-neutral-700"
          @click="openvpnLogsCollapsed = !openvpnLogsCollapsed"
          :title="openvpnLogsCollapsed ? 'Expand logs' : 'Collapse logs'"
        >
          <svg v-if="openvpnLogsCollapsed" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 12H4" />
          </svg>
        </button>
      </div>
      <pre v-show="!openvpnLogsCollapsed" class="text-xs bg-black/60 text-green-200 rounded-md p-2 max-h-48 overflow-auto nice-scroll">{{ store.openvpnLogs.join('\n') }}</pre>
    </div>
  </section>
</template>


