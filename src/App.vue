<script setup lang="ts">
import ConfigInput from '@src/components/ConfigInput.vue'
//import ConnectButton from '@src/components/ConnectButton.vue'
import IpFlag from '@src/components/IpFlag.vue'
import LoadingSpinner from '@src/components/LoadingSpinner.vue'
import ConfigList from '@src/components/ConfigList.vue'
import LogsPanel from '@src/components/LogsPanel.vue'
import ConnectionStatus from '@src/components/ConnectionStatus.vue'
import Settings from '@src/components/Settings.vue'
import OpenVpnSection from '@src/components/OpenVpnSection.vue'
import { onMounted } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()
onMounted(() => store.init())
</script>

<template>
  <div class="h-full bg-gray-50 dark:bg-neutral-900 text-gray-900 dark:text-gray-100">
    <div class="mx-auto h-full p-3 sm:p-4 md:p-6 flex flex-col gap-4 md:gap-6">
      <header class="flex items-center justify-between gap-3 shrink-0">
        <img src="/app-icon.png" alt="App icon" class="w-12 h-12 sm:w-14 sm:h-14 md:w-16 md:h-16 shrink-0" />
        <div class="flex items-center gap-2">
         
          <h1 class="text-2xl font-semibold">CrabSock</h1>
        </div>
        <IpFlag />
      </header>


      <!-- Loading State -->
      <section v-if="store.status === 'connecting'" class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700 shrink-0">
        <LoadingSpinner />
      </section>

      <!-- Main Content Grid -->
      <div v-else class="grid grid-cols-1 sm:grid-cols-2 gap-4 md:gap-6 flex-1 min-h-0">
        <!-- Left Column: Config Input and Status -->
        <div class="flex flex-col gap-4 md:gap-6 min-h-0 overflow-y-auto nice-scroll pr-1">
          <!-- Connection Status -->
          <ConnectionStatus />
          
          <!-- Config Input State -->
          <section v-if="store.showConfig" class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700 p-4">
            <ConfigInput />
          </section>


          <!-- Connect Button -->
<!--          <section  v-if="!store.showConfig" class="flex items-center gap-3">-->
<!--            <ConnectButton />-->
<!--          </section>-->
          <OpenVpnSection />
        </div>

        <!-- Right Column: Configs and Logs -->
        <div class="flex flex-col gap-4 md:gap-6 min-h-0 overflow-y-auto nice-scroll pr-1">
          <ConfigList />

          <Settings />
          <LogsPanel v-if="store.showLogs" />
        </div>
      </div>
    </div>
  </div>
</template>
