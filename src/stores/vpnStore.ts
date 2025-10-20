import { defineStore } from 'pinia'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

type Status = 'connected' | 'disconnected' | 'connecting'

interface ParsedConfig {
  proxy_type: string
  name: string
  server: string
  port: number
  password?: string
  method?: string
  uuid?: string
  security?: string
  network?: string
  tls?: boolean
  sni?: string
  skip_cert_verify?: boolean
  alpn?: string[]
  ws_path?: string
  ws_headers?: Record<string, string>
}

interface LogEntry {
  timestamp: Date
  level: 'info' | 'warn' | 'error'
  message: string
  source: 'frontend' | 'backend'
}

interface AppSettings {
  use_system_proxy: boolean
  autorun: boolean
  split_http_only: boolean
  tun_mode: boolean
}

interface ConfigFile {
  configs: ParsedConfig[]
  settings: AppSettings
}

export const useVpnStore = defineStore('vpn', {
  state: () => ({
    status: 'disconnected' as Status,
    isBusy: false,
    rawConfig: '',
    parsedConfig: null as ParsedConfig | null,
    configs: [] as ParsedConfig[],
    ip: '',
    country: '',
    showConfig: true,
    logs: [] as LogEntry[],
    error: null as string | null,
    showLogs: true,
    settings: {
      use_system_proxy: false,
      autorun: false,
      split_http_only: false,
      tun_mode: false,
    },
    configPath: '',
  }),
  actions: {
    addLog(level: 'info' | 'warn' | 'error', message: string, source: 'frontend' | 'backend' = 'frontend') {
      this.logs.push({
        timestamp: new Date(),
        level,
        message,
        source
      })
      // Ограничиваем количество логов
      if (this.logs.length > 100) {
        this.logs = this.logs.slice(-100)
      }
    },
    
    setError(error: string | null) {
      this.error = error
      if (error) {
        this.addLog('error', error, 'frontend')
      }
    },

    async init() {
      console.log('[FRONTEND] Initializing VPN store')
      this.addLog('info', 'Initializing VPN store', 'frontend')

      // Загружаем конфиги из файловой системы
      try {
        const configFile = await invoke('load_configs') as ConfigFile
        this.configs = configFile.configs
        this.settings = configFile.settings
        this.addLog('info', `Loaded ${configFile.configs.length} configs from file system`, 'frontend')
        
        // Получаем путь к конфигу
        this.configPath = await invoke('get_config_path') as string
        this.addLog('info', `Config path: ${this.configPath}`, 'frontend')
      } catch (e) {
        this.addLog('error', `Failed to load configs: ${e}`, 'frontend')
      }

      // Listen for backend status events
      listen('status', (e: any) => {
        const payload = e.payload as { status: Status }
        console.log('[FRONTEND] Received status event:', payload)
        this.status = payload.status
        this.addLog('info', `Status changed to: ${payload.status}`, 'backend')
      })

      // Listen for IP verification events
      listen('ip_verified', (e: any) => {
        const ipInfo = e.payload as { ip: string; country?: string }
        console.log('[FRONTEND] Received ip_verified event:', ipInfo)
        this.ip = ipInfo.ip
        this.country = ipInfo.country || ''
        this.addLog('info', `IP verified: ${ipInfo.ip} (${ipInfo.country || 'Unknown'})`, 'backend')
      })

      // Listen for combined connection events
      listen('connection_update', (e: any) => {
        const payload = e.payload as { status: Status; ip?: string; country?: string }
        console.log('[FRONTEND] Received connection_update event:', payload)
        console.log('[FRONTEND] Current state before update:', { status: this.status, ip: this.ip, country: this.country })

        this.status = payload.status
        if (payload.ip) {
          this.ip = payload.ip
        }
        if (payload.country) {
          this.country = payload.country
        }

        console.log('[FRONTEND] State after update:', { status: this.status, ip: this.ip, country: this.country })
        this.addLog('info', `Connection updated: ${payload.status} ${payload.ip ? `(${payload.ip})` : ''}`, 'backend')
      })

      // Listen for backend error events with details
      listen('error', (e: any) => {
        const payload = e.payload as { message?: string }
        const msg = payload?.message || 'Unknown backend error'
        console.log('[FRONTEND] Received error event:', msg)
        this.addLog('error', msg, 'backend')
        this.error = msg
        this.status = 'disconnected'
      })

      // Start connection monitoring
      try {
        await invoke('start_connection_monitoring')
        this.addLog('info', 'Connection monitoring started', 'frontend')
      } catch (e) {
        this.addLog('error', `Failed to start monitoring: ${e}`, 'frontend')
      }
    },
    
    setRawConfig(v: string) {
      this.rawConfig = v
      this.addLog('info', 'Config text updated', 'frontend')
    },
    
    updateSettings(p: Partial<{ use_system_proxy: boolean; autorun: boolean; split_http_only: boolean; tun_mode: boolean }>) {
      this.settings = { ...this.settings, ...p }
      this.addLog('info', 'Settings updated', 'frontend')
      
      // Сохраняем настройки в файловую систему
      invoke('update_settings', { settings: this.settings }).catch(e => {
        this.addLog('error', `Failed to save settings: ${e}`, 'frontend')
      })
    },
    
    async applyConfig() {
      if (!this.rawConfig.trim()) {
        this.setError('Config cannot be empty')
        return false
      }

      this.isBusy = true
      this.setError(null)
      this.addLog('info', 'Validating config...', 'frontend')
      
      try {
        // Parse config to validate it
        const parsedConfig = await invoke('parse_proxy_config', { configString: this.rawConfig }) as ParsedConfig
        this.parsedConfig = parsedConfig
        
        // Добавляем в список конфигов если его там нет
        const exists = this.configs.some(c => 
          c.server === parsedConfig.server && 
          c.port === parsedConfig.port && 
          c.proxy_type === parsedConfig.proxy_type
        )
        
        if (!exists) {
          this.configs.push(parsedConfig)
          this.addLog('info', `Config added: ${parsedConfig.name}`, 'frontend')
          
          // Сохраняем конфиг в файловую систему
          try {
            await invoke('save_config', { config: parsedConfig })
            this.addLog('info', 'Config saved to file system', 'frontend')
          } catch (e) {
            this.addLog('error', `Failed to save config: ${e}`, 'frontend')
          }
        } else {
          this.addLog('info', `Config validated: ${parsedConfig.name}`, 'frontend')
        }
        
        return true
      } catch (e) {
        const errorMsg = `Config validation failed: ${e}`
        this.setError(errorMsg)
        this.addLog('error', errorMsg, 'frontend')
        return false
      } finally {
        this.isBusy = false
      }
    },
    async saveSettings() {
      this.isBusy = true
      try {
        // Simulate settings save delay
        await new Promise(resolve => setTimeout(resolve, 300))
      } finally {
        this.isBusy = false
      }
    },
    parseConfig(): { server: string; server_port: number; password: string; method: string } | null {
      const t = this.rawConfig.trim()
      if (!t) return null
      
      // For now, just return the raw config as-is
      // The actual parsing will be done on the Rust side
      try {
        if (t.startsWith('{')) {
          const j = JSON.parse(t)
          return {
            server: j.server,
            server_port: Number(j.server_port),
            password: j.password,
            method: j.method,
          }
        }
        // ss:// method:password@host:port style - let Rust handle it
        if (t.startsWith('ss://')) {
          // Return a placeholder, actual parsing will be done in connect()
          return {
            server: '',
            server_port: 0,
            password: '',
            method: '',
          }
        }
      } catch (e) {
        console.error('parseConfig failed', e)
      }
      return null
    },
    async connect() {
      if (!this.parsedConfig) {
        this.setError('No valid config available. Please apply a config first.')
        return
      }
      
      this.isBusy = true
      this.status = 'connecting'
      this.setError(null)
      this.addLog('info', `Connecting to ${this.parsedConfig.name}...`, 'frontend')
      
      try {
        await invoke('connect_vpn', { config: this.parsedConfig })
        // Статус и IP будут обновлены через события от бэкенда
        this.showConfig = false
        this.addLog('info', 'Connection request sent successfully', 'frontend')
      } catch (e) {
        const errorMsg = `Connection failed: ${e}`
        this.setError(errorMsg)
        this.addLog('error', errorMsg, 'frontend')
        this.status = 'disconnected'
      } finally {
        this.isBusy = false
      }
    },
    async disconnect() {
      this.isBusy = true
      this.addLog('info', 'Disconnecting...', 'frontend')
      try {
        await invoke('disconnect_vpn')
        this.status = 'disconnected'
        this.showConfig = true
        this.addLog('info', 'Disconnected successfully', 'frontend')
      } catch (e) {
        const errorMsg = `Disconnect failed: ${e}`
        this.setError(errorMsg)
        this.addLog('error', errorMsg, 'frontend')
      } finally {
        this.isBusy = false
      }
    },
    
    async refreshIp() {
      try {
        const info = await invoke('get_ip')
        this.ip = (info as { ip?: string }).ip ?? ''
        this.country = (info as { country?: string }).country ?? ''
        this.addLog('info', `IP updated: ${this.ip} (${this.country})`, 'frontend')
      } catch (e) {
        this.addLog('error', `Failed to refresh IP: ${e}`, 'frontend')
        this.ip = ''
        this.country = ''
      }
    },
    
    showConfigInput() {
      this.showConfig = true
      this.addLog('info', 'Showing config input', 'frontend')
    },
    
    selectConfig(config: ParsedConfig) {
      this.parsedConfig = config
      this.rawConfig = this.configToString(config)
      this.addLog('info', `Selected config: ${config.name}`, 'frontend')
    },
    
    removeConfig(config: ParsedConfig) {
      this.configs = this.configs.filter(c =>
        !(c.server === config.server && c.port === config.port && c.proxy_type === config.proxy_type)
      )
      this.addLog('info', `Removed config: ${config.name}`, 'frontend')
      
      // Удаляем конфиг из файловой системы
      invoke('remove_config', { config }).catch(e => {
        this.addLog('error', `Failed to remove config: ${e}`, 'frontend')
      })
    },
    
    clearLogs() {
      this.logs = []
      this.addLog('info', 'Logs cleared', 'frontend')
    },
    
    configToString(config: ParsedConfig): string {
      if (config.proxy_type === 'Shadowsocks') {
        const method = config.method || 'chacha20-ietf-poly1305'
        const password = config.password || ''
        // Traditional format: ss://base64(method:password)@server:port
        const creds = btoa(`${method}:${password}`)
        return `ss://${creds}@${config.server}:${config.port}`
      } else if (config.proxy_type === 'VMess') {
        const vmessConfig = {
          v: '2',
          ps: config.name,
          add: config.server,
          port: config.port,
          id: config.uuid,
          aid: '0',
          scy: 'auto',
          net: config.network || 'tcp',
          type: 'none',
          host: config.sni || '',
          path: config.ws_path || '',
          tls: config.tls ? 'tls' : '',
          sni: config.sni || '',
          alpn: config.alpn?.join(',') || ''
        }
        const encoded = btoa(JSON.stringify(vmessConfig))
        return `vmess://${encoded}`
      }
      return JSON.stringify(config)
    },
  },
})


