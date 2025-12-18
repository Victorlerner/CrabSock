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
  // VLESS / REALITY extras
  flow?: string
  fingerprint?: string // fp
  reality_public_key?: string // pbk
  reality_short_id?: string // sid
  reality_spx?: string // spx
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
    routingMode: 'systemproxy' as 'systemproxy' | 'tun',
    // OpenVPN state
    openvpnConfigs: [] as { name: string; path: string; display_name?: string; remote?: string }[],
    openvpnStatus: 'disconnected' as Status,
    openvpnActiveConfig: '' as string,
    openvpnLogs: [] as string[],
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

      // Load routing mode from backend settings
      try {
        const settings = await invoke('get_settings') as { routing_mode?: string }
        const mode = (settings?.routing_mode || 'SystemProxy').toString().toLowerCase()
        this.routingMode = mode === 'tun' ? 'tun' : 'systemproxy'
      } catch (e) {
        // ignore, keep default
      }

      // Listen for backend status events
      listen('status', (e: any) => {
        const payload = e.payload as { status: Status }
        console.log('[FRONTEND] Received status event:', payload)
        this.status = payload.status
        this.addLog('info', `Status changed to: ${payload.status}`, 'backend')
        if (payload.status === 'disconnected') {
          // При переходе в disconnected обновляем реальный внешний IP
          this.refreshIp().catch(err => {
            this.addLog('error', `Failed to refresh IP on disconnect: ${err}`, 'frontend')
          })
        }
      })

      // OpenVPN events
      listen('openvpn-status', (e: any) => {
        const payload = e.payload as { status: Status; detail?: string }
        this.openvpnStatus = payload.status
        this.addLog('info', `[OpenVPN] ${payload.status}${payload?.detail ? `: ${payload.detail}` : ''}`, 'backend')
      })

      // Routing mode override on relaunch (elevated) - keep UI select in sync
      listen('routing-mode', (e: any) => {
        const payload = e.payload as { mode?: string }
        const m = (payload?.mode || '').toString().toLowerCase()
        this.routingMode = m === 'tun' ? 'tun' : 'systemproxy'
        this.addLog('info', `[Routing] Mode set to ${this.routingMode} by backend`, 'backend')
      })
      listen('openvpn-log', (e: any) => {
        const line = String(e.payload ?? '')
        if (!line) return
        this.openvpnLogs.push(line)
        if (this.openvpnLogs.length > 500) this.openvpnLogs = this.openvpnLogs.slice(-500)
        // Mirror into common Logs panel
        // this.addLog('info', `[OpenVPN] ${line}`, 'backend')
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

      // Restore last selected config (for showing active/disconnect button after restart/elevation relaunch)
      try {
        const raw = localStorage.getItem('crabsock:last_selected_config')
        if (raw) {
          const saved = JSON.parse(raw) as { server?: string; port?: number; proxy_type?: string; name?: string }
          const found = this.configs.find(c =>
            (saved.name && c.name === saved.name) ||
            (saved.server && saved.port && saved.proxy_type &&
              c.server === saved.server && c.port === saved.port && c.proxy_type === saved.proxy_type)
          )
          if (found) {
            this.parsedConfig = found
            this.rawConfig = this.configToString(found)
          }
        }
      } catch { /* ignore */ }

      // Sync initial status from backend (important when we auto-connect before frontend listeners attach)
      try {
        const s = String(await invoke('get_status') as string).toLowerCase()
        const mapped: Status = (s === 'connected' || s === 'connecting') ? (s as Status) : 'disconnected'
        this.status = mapped
        if (mapped !== 'disconnected') {
          this.showConfig = false
        }
      } catch (e) {
        // ignore
      }

      // На старте приложения показываем текущий внешний IP (без VPN)
      try {
        await this.refreshIp()
      } catch (e) {
        // refreshIp уже залогирует ошибку
      }

      // Fetch OpenVPN current status and recent logs to populate UI after slow start or reload
      try {
        const st = await invoke('openvpn_current_status') as { status: Status, detail?: string }
        if (st?.status) {
          this.openvpnStatus = st.status
          this.addLog('info', `[OpenVPN] ${st.status}${st?.detail ? `: ${st.detail}` : ''}`, 'backend')
        }
        const recent = await invoke('openvpn_get_recent_logs', { limit: 200 }) as string[]
        if (recent && recent.length) {
          this.openvpnLogs.push(...recent)
          if (this.openvpnLogs.length > 500) this.openvpnLogs = this.openvpnLogs.slice(-500)
          // Mirror into common Logs panel
          for (const ln of recent) {
            this.addLog('info', `[OpenVPN] ${ln}`, 'backend')
          }
        }
        // Double-check process status in case we missed early events
        const tuple = await invoke('openvpn_status') as [boolean, boolean] // [running, connected]
        const running = !!tuple?.[0]
        const connected = !!tuple?.[1]
        if (connected) {
          this.openvpnStatus = 'connected'
        } else if (running && this.openvpnStatus !== 'connected') {
          this.openvpnStatus = 'connecting'
          // schedule a short retry to catch late 'connected'
          setTimeout(async () => {
            try {
              const st2 = await invoke('openvpn_current_status') as { status: Status }
              if (st2?.status) this.openvpnStatus = st2.status
            } catch {}
          }, 1200)
        }
      } catch (e) {
        // optional; ignore if backend doesn't have any state yet
      }
    },
    async refreshOpenVpnConfigs() {
      try {
        const items = await invoke('openvpn_list_configs') as { name: string; path: string }[]
        this.openvpnConfigs = items
      } catch (e) {
        this.addLog('error', `Failed to list OpenVPN configs: ${e}`, 'frontend')
      }
    },
    async uploadOpenVpnConfig(file: File) {
      const name = file.name.replace(/\.ovpn$/i, '')
      const content = await file.text()
      try {
        await invoke('openvpn_add_config', { name, content })
        await this.refreshOpenVpnConfigs()
        this.addLog('info', `OpenVPN config saved: ${file.name}`, 'frontend')
      } catch (e) {
        this.addLog('error', `Failed to save OpenVPN config: ${e}`, 'frontend')
      }
    },
    async connectOpenVpn(name: string) {
      this.openvpnActiveConfig = name
      this.openvpnStatus = 'connecting'
      try {
        await invoke('openvpn_connect', { name })
      } catch (e) {
        this.openvpnStatus = 'disconnected'
        this.addLog('error', `OpenVPN connect failed: ${e}`, 'frontend')
      }
    },
    async disconnectOpenVpn() {
      try {
        await invoke('openvpn_disconnect')
        this.openvpnStatus = 'disconnected'
        this.openvpnActiveConfig = ''
        // Hide logs on disconnect
        this.openvpnLogs = []
      } catch (e) {
        this.addLog('error', `OpenVPN disconnect failed: ${e}`, 'frontend')
      }
    },
    async removeOpenVpnConfig(name: string) {
      try {
        await invoke('openvpn_remove_config', { name })
        await this.refreshOpenVpnConfigs()
      } catch (e) {
        this.addLog('error', `Failed to remove OpenVPN config: ${e}`, 'frontend')
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

    async setRoutingMode(mode: 'systemproxy' | 'tun') {
      try {
        await invoke('set_routing_mode', { mode })
        this.routingMode = mode
        this.addLog('info', `Routing mode set to ${mode}`, 'frontend')
      } catch (e) {
        this.addLog('error', `Failed to set routing mode: ${e}`, 'frontend')
      }
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
        // После отключения показываем реальный IP
        await this.refreshIp()
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
      try {
        localStorage.setItem('crabsock:last_selected_config', JSON.stringify({
          name: config.name,
          server: config.server,
          port: config.port,
          proxy_type: config.proxy_type,
        }))
      } catch { /* ignore */ }
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
      } else if (config.proxy_type === 'VLESS') {
        const uuid = config.uuid || ''
        const qs = new URLSearchParams()
        // VLESS requires encryption=none when using TLS/WS
        qs.set('encryption', 'none')
        if (config.security === 'reality') {
          qs.set('security', 'reality')
          if (config.reality_public_key) qs.set('pbk', config.reality_public_key)
          if (config.reality_short_id) qs.set('sid', config.reality_short_id)
          if (config.reality_spx) qs.set('spx', config.reality_spx)
          if (config.fingerprint) qs.set('fp', config.fingerprint)
          if (config.flow) qs.set('flow', config.flow)
        } else if (config.tls) {
          qs.set('security', 'tls')
        }
        if (config.sni) qs.set('sni', config.sni)
        if (config.alpn && config.alpn.length) qs.set('alpn', config.alpn.join(','))
        const net = config.network || 'tcp'
        qs.set('type', net)
        if (net === 'ws') {
          if (config.ws_path) qs.set('path', config.ws_path)
          const hostHeader = config.ws_headers?.Host || config.sni
          if (hostHeader) qs.set('host', hostHeader)
        }
        if (config.skip_cert_verify) qs.set('allowInsecure', '1')
        const tag = encodeURIComponent(config.name || `${config.server}:${config.port}`)
        return `vless://${uuid}@${config.server}:${config.port}?${qs.toString()}#${tag}`
      }
      return JSON.stringify(config)
    },
  },
})


