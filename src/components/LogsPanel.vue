<script setup lang="ts">
import { computed } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()

const logs = computed(() => store.logs.slice().reverse()) // Показываем последние логи сверху

function getLogIcon(level: string) {
  switch (level) {
    case 'error':
      return 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
    case 'warn':
      return 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z'
    default:
      return 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
  }
}

function getLogColor(level: string) {
  switch (level) {
    case 'error':
      return 'text-red-600 dark:text-red-400'
    case 'warn':
      return 'text-yellow-600 dark:text-yellow-400'
    default:
      return 'text-blue-600 dark:text-blue-400'
  }
}

function formatTime(date: Date) {
  return date.toLocaleTimeString()
}
</script>

<template>
  <div class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700">
    <div class="p-4 border-b border-gray-200/60 dark:border-neutral-700">
      <div class="flex items-center justify-between">
        <h3 class="text-lg font-semibold">Logs</h3>
        <div class="flex items-center gap-2">
          <span class="text-sm text-gray-500 dark:text-gray-400">{{ store.logs.length }} entries</span>
          <button 
            @click="store.clearLogs()"
            class="px-2 py-1 text-xs rounded-md bg-gray-100 dark:bg-neutral-700 hover:bg-gray-200 dark:hover:bg-neutral-600 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>
    </div>
    
    <div class="max-h-64 overflow-y-auto nice-scroll">
      <div v-if="logs.length === 0" class="p-4 text-center text-gray-500 dark:text-gray-400">
        No logs yet
      </div>
      
      <div v-else class="divide-y divide-gray-200/60 dark:divide-neutral-700">
        <div 
          v-for="log in logs" 
          :key="`${log.timestamp.getTime()}-${log.message}`"
          class="p-3 hover:bg-gray-50 dark:hover:bg-neutral-700/50 transition-colors"
        >
          <div class="flex items-start gap-3">
            <svg 
              class="w-4 h-4 mt-0.5 flex-shrink-0" 
              :class="getLogColor(log.level)"
              fill="none" 
              stroke="currentColor" 
              viewBox="0 0 24 24"
            >
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="getLogIcon(log.level)"></path>
            </svg>
            
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                <span class="text-xs font-mono text-gray-500 dark:text-gray-400">
                  {{ formatTime(log.timestamp) }}
                </span>
                <span 
                  class="text-xs px-1.5 py-0.5 rounded"
                  :class="{
                    'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200': log.level === 'error',
                    'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200': log.level === 'warn',
                    'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200': log.level === 'info'
                  }"
                >
                  {{ log.level.toUpperCase() }}
                </span>
                <span 
                  class="text-xs px-1.5 py-0.5 rounded bg-gray-100 dark:bg-neutral-700 text-gray-600 dark:text-gray-300"
                >
                  {{ log.source }}
                </span>
              </div>
              <p class="text-sm text-gray-900 dark:text-gray-100 break-words">
                {{ log.message }}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
