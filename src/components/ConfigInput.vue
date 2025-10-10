<script setup lang="ts">
import { ref, watch } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()
const configText = ref(store.rawConfig)

watch(() => store.rawConfig, (newVal) => {
  configText.value = newVal
})

async function apply() {
  store.setRawConfig(configText.value)
  const success = await store.applyConfig()
  if (success) {
    // Показываем успешное сообщение
    store.addLog('info', 'Config applied successfully!', 'frontend')
  }
}
</script>

<template>
  <div class="space-y-3">
    <!-- Error Display -->
    <div v-if="store.error" class="p-3 rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
      <div class="flex items-center gap-2">
        <svg class="w-4 h-4 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>
        <span class="text-sm text-red-800 dark:text-red-200">{{ store.error }}</span>
        <button @click="store.setError(null)" class="ml-auto text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-200">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
          </svg>
        </button>
      </div>
    </div>

    <!-- Success Message -->
    <div v-if="store.parsedConfig && !store.error" class="p-3 rounded-md bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800">
      <div class="flex items-center gap-2">
        <svg class="w-4 h-4 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
        </svg>
        <span class="text-sm text-green-800 dark:text-green-200">
          Config validated: {{ store.parsedConfig.name }} ({{ store.parsedConfig.proxy_type }})
        </span>
      </div>
    </div>

    <label for="config-textarea" class="text-sm font-medium">Proxy Configuration</label>
    <textarea
      id="config-textarea"
      v-model="configText"
      class="w-full h-32 rounded-md border border-gray-300 dark:border-neutral-600 bg-white dark:bg-neutral-900 p-2 font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:focus:ring-blue-400 dark:focus:border-blue-400 transition-all duration-200 resize-none"
      placeholder="ss://, vmess://, or JSON config"
    />
    
    <div class="flex justify-between items-center">
      <div class="text-xs text-gray-500 dark:text-gray-400">
        {{ store.configs.length }} config(s) saved
      </div>
      <button 
        class="px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center gap-2"
        :disabled="store.isBusy || !configText.trim()"
        @click="apply"
      >
        <div v-if="store.isBusy" class="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
        <svg v-else class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
        </svg>
        Apply
      </button>
    </div>
  </div>
</template>


