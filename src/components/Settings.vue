<script setup lang="ts">
import { ref } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()
const useSystemProxy = ref(false)
const autorun = ref(false)
const splitHttpOnly = ref(false)

function save() {
  store.updateSettings({ useSystemProxy: useSystemProxy.value, autorun: autorun.value, splitHttpOnly: splitHttpOnly.value })
  store.saveSettings()
}
</script>

<template>
  <div class="ml-auto flex items-center gap-3">
    <label class="inline-flex items-center gap-2 text-sm hover:text-gray-900 dark:hover:text-gray-100 cursor-pointer transition-colors">
      <input type="checkbox" v-model="useSystemProxy" class="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600" /> System proxy
    </label>
    <label class="inline-flex items-center gap-2 text-sm hover:text-gray-900 dark:hover:text-gray-100 cursor-pointer transition-colors">
      <input type="checkbox" v-model="autorun" class="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600" /> Autostart
    </label>
    <label class="inline-flex items-center gap-2 text-sm hover:text-gray-900 dark:hover:text-gray-100 cursor-pointer transition-colors">
      <input type="checkbox" v-model="splitHttpOnly" class="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600" /> Split HTTP(S)
    </label>
    <button 
      class="px-3 py-1.5 rounded-md bg-gray-200 dark:bg-neutral-700 hover:bg-gray-300 dark:hover:bg-neutral-600 active:bg-gray-400 dark:active:bg-neutral-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center gap-2"
      :disabled="store.isBusy"
      @click="save"
    >
      <div v-if="store.isBusy" class="w-3 h-3 border-2 border-gray-600 dark:border-gray-300 border-t-transparent rounded-full animate-spin"></div>
      <svg v-else class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
      </svg>
      Save
    </button>
  </div>
</template>


