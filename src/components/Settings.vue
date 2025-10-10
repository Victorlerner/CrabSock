<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'
import { invoke } from '@tauri-apps/api/core'

const store = useVpnStore()
const useSystemProxy = ref(store.settings.use_system_proxy)
const autorun = ref(store.settings.autorun)
const splitHttpOnly = ref(store.settings.split_http_only)
const tunMode = ref(store.settings.tun_mode)

// Отладочная информация
console.log('[SETTINGS] Initial settings:', store.settings)
console.log('[SETTINGS] tunMode ref value:', tunMode.value)

// Следим за изменениями в store
watch(() => store.settings, (newSettings) => {
  console.log('[SETTINGS] Settings changed:', newSettings)
  useSystemProxy.value = newSettings.use_system_proxy
  autorun.value = newSettings.autorun
  splitHttpOnly.value = newSettings.split_http_only
  tunMode.value = newSettings.tun_mode
  console.log('[SETTINGS] Updated tunMode ref:', tunMode.value)
}, { deep: true })

// Следим за изменениями чекбокса системного прокси
watch(useSystemProxy, async (newValue) => {
  if (newValue) {
    // Включаем системный прокси
    try {
      await invoke('set_system_proxy')
      store.addLog('info', 'System proxy enabled', 'frontend')
    } catch (e) {
      store.addLog('error', `Failed to enable system proxy: ${e}`, 'frontend')
      useSystemProxy.value = false // Откатываем изменение
    }
  } else {
    // Отключаем системный прокси
    try {
      await invoke('clear_system_proxy')
      store.addLog('info', 'System proxy disabled', 'frontend')
    } catch (e) {
      store.addLog('error', `Failed to disable system proxy: ${e}`, 'frontend')
    }
  }
  
  // Сохраняем настройки
  store.updateSettings({ 
    use_system_proxy: useSystemProxy.value, 
    autorun: autorun.value, 
    split_http_only: splitHttpOnly.value 
  })
})

// Следим за изменениями чекбокса TUN режима
watch(tunMode, async (newValue) => {
  if (newValue) {
    // Включаем TUN режим
    try {
      await invoke('enable_tun_mode')
      store.addLog('info', 'TUN mode enabled - all traffic routed through VPN', 'frontend')
    } catch (e) {
      store.addLog('error', `Failed to enable TUN mode: ${e}`, 'frontend')
      
      // Если ошибка связана с правами, показываем popup
      if (e.toString().includes('permissions') || e.toString().includes('sudo') || e.toString().includes('capability')) {
        const result = await showTunPermissionDialog()
        
        if (result === 'grant') {
          try {
            // Сначала проверяем, есть ли уже capability
            const hasCapability = await invoke('check_tun_capability_command')
            
                        if (hasCapability) {
                          store.addLog('info', 'TUN capability already set, trying to enable TUN mode...', 'frontend')
                          // Попробуем включить TUN режим еще раз
                          try {
                            await invoke('enable_tun_mode')
                            store.addLog('info', 'TUN mode enabled successfully without restart!', 'frontend')
                            return // Успешно включили без перезапуска
                          } catch (retryError) {
                            store.addLog('error', `Failed to enable TUN mode even with capability: ${retryError}`, 'frontend')
                            
                            // Если ошибка связана с development mode, предлагаем собрать release
                            if (retryError.toString().includes('development mode') || retryError.toString().includes('release version')) {
                              const buildRelease = await showBuildReleaseDialog()
                              
                              if (buildRelease === 'yes') {
                                try {
                                  store.addLog('info', 'Building release version...', 'frontend')
                                  const buildResult = await invoke('build_release_version')
                                  store.addLog('info', buildResult, 'frontend')
                                  
                                  // Показываем сообщение о том, что нужно запустить release версию
                                  await showRunReleaseDialog()
                                } catch (buildError) {
                                  store.addLog('error', `Failed to build release version: ${buildError}`, 'frontend')
                                }
                              }
                            }
                            
                            tunMode.value = false
                            return
                          }
                        }
            
            store.addLog('info', 'Requesting TUN permissions...', 'frontend')
            const permissionResult = await invoke('request_tun_permissions')
            
                if (permissionResult.success) {
                  store.addLog('info', permissionResult.message, 'frontend')
                  
                  if (permissionResult.needs_restart) {
                    // Не перезапускаем, а предлагаем собрать release версию
                    store.addLog('info', 'Capability set successfully. Building release version for TUN Mode...', 'frontend')
                    
                    try {
                      const buildResult = await invoke('build_release_version')
                      store.addLog('info', buildResult, 'frontend')
                      
                      // Показываем сообщение о том, что нужно запустить release версию
                      await showRunReleaseDialog()
                    } catch (buildError) {
                      store.addLog('error', `Failed to build release version: ${buildError}`, 'frontend')
                    }
                  }
                } else {
                  store.addLog('error', permissionResult.message, 'frontend')
                  
                  // Если pkexec заблокирован, предлагаем альтернативу
                  if (permissionResult.message.includes('locked out') || permissionResult.message.includes('Request dismissed')) {
                    const useSudo = await showSudoAlternativeDialog()
                    
                    if (useSudo === 'yes') {
                      try {
                        store.addLog('info', 'Trying sudo alternative...', 'frontend')
                        const sudoResult = await invoke('request_tun_permissions_sudo')
                        
                        if (sudoResult.success) {
                          store.addLog('info', sudoResult.message, 'frontend')
                          
                          if (sudoResult.needs_restart) {
                            // Не перезапускаем, а предлагаем собрать release версию
                            store.addLog('info', 'Capability set successfully via sudo. Building release version for TUN Mode...', 'frontend')
                            
                            try {
                              const buildResult = await invoke('build_release_version')
                              store.addLog('info', buildResult, 'frontend')
                              
                              // Показываем сообщение о том, что нужно запустить release версию
                              await showRunReleaseDialog()
                            } catch (buildError) {
                              store.addLog('error', `Failed to build release version: ${buildError}`, 'frontend')
                            }
                          }
                        } else {
                          store.addLog('error', sudoResult.message, 'frontend')
                          tunMode.value = false
                        }
                      } catch (sudoError) {
                        store.addLog('error', `Failed to use sudo: ${sudoError}`, 'frontend')
                        tunMode.value = false
                      }
                    } else {
                      tunMode.value = false
                    }
                  } else {
                    tunMode.value = false
                  }
                }
          } catch (permError) {
            store.addLog('error', `Failed to request permissions: ${permError}`, 'frontend')
            tunMode.value = false // Откатываем изменение
          }
        } else {
          tunMode.value = false // Откатываем изменение
        }
      } else {
        tunMode.value = false // Откатываем изменение
      }
    }
  } else {
    // Отключаем TUN режим
    try {
      await invoke('disable_tun_mode')
      store.addLog('info', 'TUN mode disabled', 'frontend')
    } catch (e) {
      store.addLog('error', `Failed to disable TUN mode: ${e}`, 'frontend')
    }
  }
  
  // Сохраняем настройки
  store.updateSettings({ 
    use_system_proxy: useSystemProxy.value, 
    autorun: autorun.value, 
    split_http_only: splitHttpOnly.value,
    tun_mode: tunMode.value
  })
})

// Функция для показа диалога запроса прав
async function showTunPermissionDialog() {
  return new Promise((resolve) => {
    const dialog = document.createElement('div')
    dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50'
    dialog.innerHTML = `
      <div class="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md mx-4 shadow-xl">
        <div class="flex items-center mb-4">
          <div class="w-10 h-10 bg-yellow-100 dark:bg-yellow-900 rounded-full flex items-center justify-center mr-3">
            <svg class="w-6 h-6 text-yellow-600 dark:text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
            </svg>
          </div>
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">TUN Mode Requires Admin Privileges</h3>
        </div>
        <p class="text-gray-600 dark:text-gray-300 mb-6">
          TUN Mode requires administrator privileges to create virtual network interfaces. 
          Would you like to grant permissions and restart the application?
        </p>
        <div class="flex justify-end space-x-3">
          <button id="cancel-btn" class="px-4 py-2 text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-gray-100 transition-colors">
            Cancel
          </button>
          <button id="grant-btn" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
            Grant Permissions
          </button>
        </div>
      </div>
    `
    
    document.body.appendChild(dialog)
    
    dialog.querySelector('#cancel-btn').addEventListener('click', () => {
      document.body.removeChild(dialog)
      resolve('cancel')
    })
    
    dialog.querySelector('#grant-btn').addEventListener('click', () => {
      document.body.removeChild(dialog)
      resolve('grant')
    })
  })
}

    // Функция для показа диалога перезапуска
    async function showRestartDialog() {
      return new Promise((resolve) => {
        const dialog = document.createElement('div')
        dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50'
        dialog.innerHTML = `
          <div class="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md mx-4 shadow-xl">
            <div class="flex items-center mb-4">
              <div class="w-10 h-10 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center mr-3">
                <svg class="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">Permissions Granted</h3>
            </div>
            <p class="text-gray-600 dark:text-gray-300 mb-6">
              Administrator privileges have been granted successfully. The application will now restart to apply the changes.
            </p>
            <div class="flex justify-end">
              <button id="ok-btn" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                OK
              </button>
            </div>
          </div>
        `
        
        document.body.appendChild(dialog)
        
        dialog.querySelector('#ok-btn').addEventListener('click', () => {
          document.body.removeChild(dialog)
          resolve()
        })
      })
    }

    // Функция для показа диалога с альтернативой sudo
    async function showSudoAlternativeDialog() {
      return new Promise((resolve) => {
        const dialog = document.createElement('div')
        dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50'
        dialog.innerHTML = `
          <div class="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md mx-4 shadow-xl">
            <div class="flex items-center mb-4">
              <div class="w-10 h-10 bg-orange-100 dark:bg-orange-900 rounded-full flex items-center justify-center mr-3">
                <svg class="w-6 h-6 text-orange-600 dark:text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                </svg>
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">pkexec Blocked</h3>
            </div>
            <p class="text-gray-600 dark:text-gray-300 mb-6">
              pkexec is temporarily blocked due to failed authentication attempts. 
              Would you like to try using sudo instead? This will open a terminal window for password input.
            </p>
            <div class="flex justify-end space-x-3">
              <button id="no-btn" class="px-4 py-2 text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-gray-100 transition-colors">
                No
              </button>
              <button id="yes-btn" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                Try sudo
              </button>
            </div>
          </div>
        `
        
        document.body.appendChild(dialog)
        
        dialog.querySelector('#no-btn').addEventListener('click', () => {
          document.body.removeChild(dialog)
          resolve('no')
        })
        
        dialog.querySelector('#yes-btn').addEventListener('click', () => {
          document.body.removeChild(dialog)
          resolve('yes')
        })
      })
    }

    // Функция для показа диалога сборки release версии
    async function showBuildReleaseDialog() {
      return new Promise((resolve) => {
        const dialog = document.createElement('div')
        dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50'
        dialog.innerHTML = `
          <div class="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md mx-4 shadow-xl">
            <div class="flex items-center mb-4">
              <div class="w-10 h-10 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center mr-3">
                <svg class="w-6 h-6 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"></path>
                </svg>
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">Development Mode Issue</h3>
            </div>
            <p class="text-gray-600 dark:text-gray-300 mb-6">
              TUN Mode requires a release build to work properly. The development version cannot create TUN interfaces even with proper capabilities.
              <br><br>
              Would you like to build a release version now?
            </p>
            <div class="flex justify-end space-x-3">
              <button id="no-btn" class="px-4 py-2 text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-gray-100 transition-colors">
                No
              </button>
              <button id="yes-btn" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                Build Release
              </button>
            </div>
          </div>
        `
        
        document.body.appendChild(dialog)
        
        dialog.querySelector('#no-btn').addEventListener('click', () => {
          document.body.removeChild(dialog)
          resolve('no')
        })
        
        dialog.querySelector('#yes-btn').addEventListener('click', () => {
          document.body.removeChild(dialog)
          resolve('yes')
        })
      })
    }

    // Функция для показа диалога запуска release версии
    async function showRunReleaseDialog() {
      return new Promise((resolve) => {
        const dialog = document.createElement('div')
        dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50'
        dialog.innerHTML = `
          <div class="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md mx-4 shadow-xl">
            <div class="flex items-center mb-4">
              <div class="w-10 h-10 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center mr-3">
                <svg class="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">Release Version Ready</h3>
            </div>
            <p class="text-gray-600 dark:text-gray-300 mb-6">
              The release version has been built successfully with TUN capabilities enabled.
              <br><br>
              To use TUN Mode, please run the release version from the terminal:
              <br><br>
              <code class="bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded text-sm">cd /home/victor/PhpstormProjects/have-fun/CrabSock/ui && ./set_capability.sh</code>
              <br><br>
              <code class="bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded text-sm">env GDK_BACKEND=x11 DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_SANDBOX=1 ./src-tauri/target/release/crab-sock</code>
            </p>
            <div class="flex justify-end">
              <button id="ok-btn" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                OK
              </button>
            </div>
          </div>
        `
        
        document.body.appendChild(dialog)
        
        dialog.querySelector('#ok-btn').addEventListener('click', () => {
          document.body.removeChild(dialog)
          resolve()
        })
      })
    }

function save() {
  store.updateSettings({ 
    use_system_proxy: useSystemProxy.value, 
    autorun: autorun.value, 
    split_http_only: splitHttpOnly.value,
    tun_mode: tunMode.value
  })
  store.saveSettings()
}
</script>

<template>
  <div class="ml-auto flex items-center gap-3">
        <label class="inline-flex items-center gap-2 text-sm hover:text-gray-900 dark:hover:text-gray-100 cursor-pointer transition-colors" title="TUN Mode: Creates virtual network interface for enhanced proxy routing">
          <input type="checkbox" v-model="tunMode" class="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600" /> TUN Mode
        </label>
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


