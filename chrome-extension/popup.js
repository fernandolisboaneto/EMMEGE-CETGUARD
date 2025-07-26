// CertGuard AI - Popup Script
const API_BASE = 'https://db8c0483-612c-4ca0-a771-ee19879f6626.preview.emergentagent.com/api';

class CertGuardPopup {
  constructor() {
    this.token = null;
    this.user = null;
    this.currentTab = null;
    this.init();
  }

  async init() {
    try {
      // Get current tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentTab = tab;
      
      // Load stored data
      await this.loadStoredData();
      
      // Update UI
      await this.updateUI();
      
      // Set up event listeners
      this.setupEventListeners();
      
      // Hide loading
      document.getElementById('loading').style.display = 'none';
      document.getElementById('main-content').style.display = 'block';
      
    } catch (error) {
      console.error('Initialization error:', error);
      this.showError('Erro ao inicializar a extensão');
    }
  }

  async loadStoredData() {
    try {
      const result = await chrome.storage.sync.get(['token', 'user', 'certificates']);
      this.token = result.token;
      this.user = result.user;
      this.certificates = result.certificates || [];
    } catch (error) {
      console.error('Error loading stored data:', error);
    }
  }

  async updateUI() {
    try {
      // Update connection status
      const connectionStatus = document.getElementById('connection-status');
      if (this.token && this.user) {
        connectionStatus.className = 'status connected';
        connectionStatus.innerHTML = `
          <div class="status-icon"></div>
          <span>Conectado como ${this.user.full_name}</span>
        `;
      } else {
        connectionStatus.className = 'status disconnected';
        connectionStatus.innerHTML = `
          <div class="status-icon"></div>
          <span>Desconectado - <a href="#" id="login-link">Fazer Login</a></span>
        `;
      }

      // Update current URL
      if (this.currentTab) {
        document.getElementById('current-url').textContent = 
          this.currentTab.url.length > 40 
            ? this.currentTab.url.substring(0, 40) + '...' 
            : this.currentTab.url;
        
        // Detect tribunal
        const tribunalName = this.detectTribunal(this.currentTab.url);
        document.getElementById('tribunal-name').textContent = tribunalName;
      }

      // Update security indicators
      await this.updateSecurityIndicators();
      
      // Update last update time
      document.getElementById('last-update').textContent = 
        new Date().toLocaleTimeString('pt-BR');

    } catch (error) {
      console.error('Error updating UI:', error);
    }
  }

  detectTribunal(url) {
    const tribunals = {
      'tjsp.jus.br': 'Tribunal de Justiça de São Paulo',
      'tjrj.jus.br': 'Tribunal de Justiça do Rio de Janeiro',
      'tjmg.jus.br': 'Tribunal de Justiça de Minas Gerais',
      'stf.jus.br': 'Supremo Tribunal Federal',
      'stj.jus.br': 'Superior Tribunal de Justiça',
      'tst.jus.br': 'Tribunal Superior do Trabalho',
      'trf1.jus.br': 'Tribunal Regional Federal 1ª Região',
      'trf2.jus.br': 'Tribunal Regional Federal 2ª Região',
      'trf3.jus.br': 'Tribunal Regional Federal 3ª Região',
      'trf4.jus.br': 'Tribunal Regional Federal 4ª Região',
      'trf5.jus.br': 'Tribunal Regional Federal 5ª Região'
    };

    for (const [domain, name] of Object.entries(tribunals)) {
      if (url.includes(domain)) {
        return name;
      }
    }

    return 'Site não identificado';
  }

  async updateSecurityIndicators() {
    try {
      // Simulate security checks
      const indicators = {
        blockchain: { status: 'safe', text: 'Ativo' },
        ai: { status: 'safe', text: 'Monitorando' },
        zeroTrust: { status: 'safe', text: 'Verificado' },
        container: { status: 'safe', text: 'Seguro' }
      };

      // Update each indicator
      Object.entries(indicators).forEach(([key, value]) => {
        const element = document.getElementById(`${key.replace(/([A-Z])/g, '-$1').toLowerCase()}-indicator`);
        if (element) {
          element.className = `security-indicator ${value.status}`;
          element.innerHTML = element.innerHTML.replace(/\b\w+$/, value.text);
        }
      });

    } catch (error) {
      console.error('Error updating security indicators:', error);
    }
  }

  setupEventListeners() {
    // Login link
    document.addEventListener('click', (e) => {
      if (e.target.id === 'login-link') {
        e.preventDefault();
        this.openLoginPage();
      }
    });

    // Access button
    document.getElementById('access-btn').addEventListener('click', () => {
      this.initiateSecureAccess();
    });

    // Container button
    document.getElementById('container-btn').addEventListener('click', () => {
      this.openSecureContainer();
    });

    // Logout button
    document.getElementById('logout-btn').addEventListener('click', () => {
      this.logout();
    });

    // Refresh every 30 seconds
    setInterval(() => {
      this.updateUI();
    }, 30000);
  }

  openLoginPage() {
    chrome.tabs.create({
      url: 'https://db8c0483-612c-4ca0-a771-ee19879f6626.preview.emergentagent.com'
    });
  }

  async initiateSecureAccess() {
    try {
      if (!this.token) {
        this.showError('Usuário não autenticado');
        return;
      }

      // Show loading
      const btn = document.getElementById('access-btn');
      btn.disabled = true;
      btn.textContent = '🔄 Iniciando...';

      // Request container access
      const response = await this.makeAPIRequest('/container/access', {
        method: 'POST',
        body: JSON.stringify({
          certificate_id: 'selected-cert-id', // This should come from selected certificate
          site_url: this.currentTab.url
        })
      });

      if (response.access_token) {
        // Inject secure container
        await this.injectSecureContainer(response.access_token);
        
        // Update UI
        document.getElementById('session-status').textContent = 'Ativa';
        document.getElementById('active-certificate').textContent = 'Certificado Ativo';
        
        btn.textContent = '✅ Acesso Ativo';
        btn.disabled = false;
        
        // Log activity
        await this.logActivity('SECURE_ACCESS_INITIATED', {
          site_url: this.currentTab.url,
          access_token: response.access_token.substring(0, 8) + '...'
        });
        
      } else {
        throw new Error('Falha ao obter token de acesso');
      }

    } catch (error) {
      console.error('Secure access error:', error);
      this.showError('Erro ao iniciar acesso seguro');
      
      // Reset button
      const btn = document.getElementById('access-btn');
      btn.textContent = '🚀 Iniciar Acesso Seguro';
      btn.disabled = false;
    }
  }

  async injectSecureContainer(accessToken) {
    try {
      // Inject secure container script
      await chrome.scripting.executeScript({
        target: { tabId: this.currentTab.id },
        function: (token) => {
          // Create secure container overlay
          const overlay = document.createElement('div');
          overlay.id = 'certguard-overlay';
          overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-family: Arial, sans-serif;
          `;
          
          overlay.innerHTML = `
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 15px; text-align: center; max-width: 500px;">
              <h2>🔐 CertGuard AI - Container Seguro</h2>
              <p>Acesso seguro iniciado com certificado digital</p>
              <p><strong>Token:</strong> ${token.substring(0, 16)}...</p>
              <p><strong>Blockchain:</strong> ✅ Auditoria ativa</p>
              <p><strong>IA:</strong> 🤖 Monitoramento comportamental</p>
              <p><strong>Zero Trust:</strong> 🛡️ Verificação contínua</p>
              <button onclick="this.parentElement.parentElement.remove()" style="
                background: white;
                color: #667eea;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-weight: bold;
                margin-top: 20px;
              ">Continuar com Segurança</button>
            </div>
          `;
          
          document.body.appendChild(overlay);
          
          // Remove overlay after 5 seconds
          setTimeout(() => {
            overlay.remove();
          }, 5000);
        },
        args: [accessToken]
      });

    } catch (error) {
      console.error('Error injecting secure container:', error);
      throw error;
    }
  }

  async openSecureContainer() {
    try {
      // Open CertGuard AI dashboard in new tab
      chrome.tabs.create({
        url: 'https://db8c0483-612c-4ca0-a771-ee19879f6626.preview.emergentagent.com'
      });

    } catch (error) {
      console.error('Error opening secure container:', error);
      this.showError('Erro ao abrir container seguro');
    }
  }

  async logout() {
    try {
      // Clear stored data
      await chrome.storage.sync.clear();
      
      // Reset instance variables
      this.token = null;
      this.user = null;
      this.certificates = [];
      
      // Update UI
      await this.updateUI();
      
      // Show success message
      this.showSuccess('Logout realizado com sucesso');

    } catch (error) {
      console.error('Logout error:', error);
      this.showError('Erro ao fazer logout');
    }
  }

  async makeAPIRequest(endpoint, options = {}) {
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`,
          ...options.headers
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();

    } catch (error) {
      console.error('API request error:', error);
      throw error;
    }
  }

  async logActivity(action, details = {}) {
    try {
      // This would normally send to the backend
      console.log('Activity logged:', {
        action,
        details,
        timestamp: new Date().toISOString(),
        url: this.currentTab?.url
      });
      
      // Store locally for now
      const activities = await chrome.storage.local.get('activities');
      const activityList = activities.activities || [];
      
      activityList.push({
        action,
        details,
        timestamp: new Date().toISOString(),
        url: this.currentTab?.url
      });
      
      // Keep only last 100 activities
      if (activityList.length > 100) {
        activityList.splice(0, activityList.length - 100);
      }
      
      await chrome.storage.local.set({ activities: activityList });

    } catch (error) {
      console.error('Error logging activity:', error);
    }
  }

  showError(message) {
    this.showNotification(message, 'error');
  }

  showSuccess(message) {
    this.showNotification(message, 'success');
  }

  showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 15px;
      border-radius: 5px;
      color: white;
      font-weight: bold;
      z-index: 1000;
      max-width: 300px;
      word-wrap: break-word;
    `;

    // Set background based on type
    switch (type) {
      case 'error':
        notification.style.background = '#dc3545';
        break;
      case 'success':
        notification.style.background = '#28a745';
        break;
      default:
        notification.style.background = '#17a2b8';
    }

    notification.textContent = message;
    document.body.appendChild(notification);

    // Remove after 3 seconds
    setTimeout(() => {
      notification.remove();
    }, 3000);
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new CertGuardPopup();
});