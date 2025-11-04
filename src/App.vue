<script setup lang="ts">
import ConfigInput from '@src/components/ConfigInput.vue'
import ConnectButton from '@src/components/ConnectButton.vue'
import IpFlag from '@src/components/IpFlag.vue'
import LoadingSpinner from '@src/components/LoadingSpinner.vue'
import ConfigList from '@src/components/ConfigList.vue'
import LogsPanel from '@src/components/LogsPanel.vue'
import ConnectionStatus from '@src/components/ConnectionStatus.vue'
import Settings from '@src/components/Settings.vue'
import { onMounted } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()
onMounted(() => store.init())
</script>

<template>
  <div class="min-h-full bg-gray-50 dark:bg-neutral-900 text-gray-900 dark:text-gray-100">
    <div class="mx-auto p-6 space-y-6">
      <header class="flex items-center justify-between">
        <img src="/app-icon.png" alt="App icon" class="w-16 h-16" />
        <div class="flex items-center gap-2">
         
          <h1 class="text-2xl font-semibold">CrabSock</h1>
        </div>
        <IpFlag />
      </header>


      <!-- Loading State -->
      <section v-if="store.status === 'connecting'" class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700">
        <LoadingSpinner />
      </section>

      <!-- Main Content Grid -->
      <div v-else class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Left Column: Config Input and Status -->
        <div class="space-y-6">
          <!-- Connection Status -->
          <ConnectionStatus />
          
          <!-- Config Input State -->
          <section v-if="store.showConfig" class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700 p-4">
            <ConfigInput />
          </section>


          <!-- Connect Button -->
          <section  v-if="!store.showConfig" class="flex items-center gap-3">
            <ConnectButton />
          </section>
        </div>

        <!-- Right Column: Configs and Logs -->
        <div class="space-y-6">
          <ConfigList />
          <Settings />
          <LogsPanel v-if="store.showLogs" />
        </div>
      </div>
    </div>
  </div>
</template>
