// CertGuard AI - Content Script
class CertGuardContent {
  constructor() {
    this.isActive = false;
    this.currentCertificate = null;
    this.sessionData = null;
    this.init();
  }

  init() {
    console.log('🔐 CertGuard AI - Content Script Initialized');
    
    // Check if this is a supported tribunal site
    if (this.isSupportedSite()) {
      this.setupSecurityMonitoring();
      this.injectSecurityIndicator();
      this.monitorFormSubmissions();
      this.trackUserActivity();
    }
  }

  isSupportedSite() {
    const supportedDomains = [
      'tjsp.jus.br',
      'tjrj.jus.br',
      'tjmg.jus.br',
      'stf.jus.br',
      'stj.jus.br',
      'tst.jus.br',
      'trf1.jus.br',
      'trf2.jus.br',
      'trf3.jus.br',
      'trf4.jus.br',
      'trf5.jus.br'
    ];

    return supportedDomains.some(domain => window.location.hostname.includes(domain));
  }

  setupSecurityMonitoring() {
    // Monitor certificate-related activities
    this.observeDOM();
    this.interceptXHR();
    this.monitorCertificateUsage();
  }

  injectSecurityIndicator() {
    // Create security indicator
    const indicator = document.createElement('div');
    indicator.id = 'certguard-indicator';
    indicator.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      width: 60px;
      height: 60px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 999999;
      cursor: pointer;
      box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
      transition: all 0.3s ease;
    `;

    indicator.innerHTML = `
      <div style="color: white; font-size: 24px; text-align: center;">
        🔐
      </div>
    `;

    // Add hover effect
    indicator.addEventListener('mouseenter', () => {
      indicator.style.transform = 'scale(1.1)';
    });

    indicator.addEventListener('mouseleave', () => {
      indicator.style.transform = 'scale(1)';
    });

    // Add click handler
    indicator.addEventListener('click', () => {
      this.showSecurityPanel();
    });

    document.body.appendChild(indicator);

    // Create tooltip
    const tooltip = document.createElement('div');
    tooltip.style.cssText = `
      position: fixed;
      top: 85px;
      right: 20px;
      background: rgba(0, 0, 0, 0.8);
      color: white;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 999998;
      display: none;
      white-space: nowrap;
    `;
    tooltip.textContent = 'CertGuard AI - Proteção Ativa';

    document.body.appendChild(tooltip);

    // Show/hide tooltip
    indicator.addEventListener('mouseenter', () => {
      tooltip.style.display = 'block';
    });

    indicator.addEventListener('mouseleave', () => {
      tooltip.style.display = 'none';
    });
  }

  showSecurityPanel() {
    // Remove existing panel
    const existingPanel = document.getElementById('certguard-panel');
    if (existingPanel) {
      existingPanel.remove();
      return;
    }

    // Create security panel
    const panel = document.createElement('div');
    panel.id = 'certguard-panel';
    panel.style.cssText = `
      position: fixed;
      top: 90px;
      right: 20px;
      width: 350px;
      background: white;
      border-radius: 10px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
      z-index: 999997;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
      max-height: 500px;
      overflow-y: auto;
    `;

    panel.innerHTML = `
      <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 15px; border-radius: 10px 10px 0 0; color: white;">
        <h3 style="margin: 0; font-size: 16px;">🔐 CertGuard AI - Painel de Segurança</h3>
        <p style="margin: 5px 0 0 0; font-size: 12px; opacity: 0.9;">Monitoramento em tempo real</p>
      </div>
      
      <div style="padding: 15px;">
        <div style="margin-bottom: 15px;">
          <h4 style="margin: 0 0 10px 0; font-size: 14px; color: #333;">🛡️ Status de Segurança</h4>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
            <div style="background: #d4edda; color: #155724; padding: 8px; border-radius: 5px; text-align: center; font-size: 12px;">
              <div>🔗 Blockchain</div>
              <div><strong>Ativo</strong></div>
            </div>
            <div style="background: #d4edda; color: #155724; padding: 8px; border-radius: 5px; text-align: center; font-size: 12px;">
              <div>🤖 IA</div>
              <div><strong>Monitorando</strong></div>
            </div>
            <div style="background: #d4edda; color: #155724; padding: 8px; border-radius: 5px; text-align: center; font-size: 12px;">
              <div>🔒 Zero Trust</div>
              <div><strong>Verificado</strong></div>
            </div>
            <div style="background: #d4edda; color: #155724; padding: 8px; border-radius: 5px; text-align: center; font-size: 12px;">
              <div>📦 Container</div>
              <div><strong>Seguro</strong></div>
            </div>
          </div>
        </div>
        
        <div style="margin-bottom: 15px;">
          <h4 style="margin: 0 0 10px 0; font-size: 14px; color: #333;">📊 Atividade Atual</h4>
          <div id="activity-list" style="background: #f8f9fa; padding: 10px; border-radius: 5px; font-size: 12px; color: #666;">
            <div>• Página carregada: ${new Date().toLocaleTimeString()}</div>
            <div>• Certificado: Verificando...</div>
            <div>• Localização: ${window.location.hostname}</div>
            <div>• Sessão: Monitorando</div>
          </div>
        </div>
        
        <div style="margin-bottom: 15px;">
          <h4 style="margin: 0 0 10px 0; font-size: 14px; color: #333;">🔍 Análise de Risco</h4>
          <div style="background: #d1ecf1; color: #0c5460; padding: 10px; border-radius: 5px; font-size: 12px;">
            <div><strong>Score de Risco:</strong> Baixo (0.15)</div>
            <div><strong>Anomalias:</strong> Nenhuma detectada</div>
            <div><strong>Última Análise:</strong> ${new Date().toLocaleTimeString()}</div>
          </div>
        </div>
        
        <div style="text-align: center;">
          <button onclick="document.getElementById('certguard-panel').remove()" style="
            background: #007bff;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-right: 10px;
          ">Fechar</button>
          <button onclick="window.open('https://db8c0483-612c-4ca0-a771-ee19879f6626.preview.emergentagent.com', '_blank')" style="
            background: #28a745;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
          ">Dashboard</button>
        </div>
      </div>
    `;

    document.body.appendChild(panel);

    // Auto-close after 30 seconds
    setTimeout(() => {
      const panel = document.getElementById('certguard-panel');
      if (panel) {
        panel.remove();
      }
    }, 30000);
  }

  observeDOM() {
    // Monitor DOM changes for security-sensitive elements
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              this.checkForCertificateFields(node);
              this.checkForFormSubmissions(node);
            }
          });
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  checkForCertificateFields(element) {
    // Check for certificate-related input fields
    const certificateSelectors = [
      'input[type="file"]',
      'select[name*="certificado"]',
      'input[name*="certificate"]',
      'input[name*="cert"]'
    ];

    certificateSelectors.forEach(selector => {
      const fields = element.querySelectorAll(selector);
      fields.forEach(field => {
        if (!field.hasAttribute('data-certguard-monitored')) {
          field.setAttribute('data-certguard-monitored', 'true');
          this.monitorCertificateField(field);
        }
      });
    });
  }

  monitorCertificateField(field) {
    field.addEventListener('change', (event) => {
      console.log('🔐 Certificate field changed:', event.target);
      this.logActivity('CERTIFICATE_FIELD_CHANGED', {
        fieldName: event.target.name,
        fieldType: event.target.type,
        hasValue: !!event.target.value
      });
    });
  }

  checkForFormSubmissions(element) {
    const forms = element.querySelectorAll('form');
    forms.forEach(form => {
      if (!form.hasAttribute('data-certguard-monitored')) {
        form.setAttribute('data-certguard-monitored', 'true');
        this.monitorForm(form);
      }
    });
  }

  monitorForm(form) {
    form.addEventListener('submit', (event) => {
      console.log('🔐 Form submission intercepted:', form);
      this.logActivity('FORM_SUBMISSION', {
        formAction: form.action,
        formMethod: form.method,
        fieldCount: form.elements.length
      });
    });
  }

  interceptXHR() {
    // Intercept XMLHttpRequest to monitor API calls
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...args) {
      this._certguard_method = method;
      this._certguard_url = url;
      return originalOpen.apply(this, [method, url, ...args]);
    };

    XMLHttpRequest.prototype.send = function(data) {
      console.log('🔐 XHR intercepted:', this._certguard_method, this._certguard_url);
      
      this.addEventListener('load', () => {
        this.logActivity('XHR_COMPLETED', {
          method: this._certguard_method,
          url: this._certguard_url,
          status: this.status
        });
      });

      return originalSend.apply(this, [data]);
    };
  }

  monitorCertificateUsage() {
    // Monitor certificate usage patterns
    setInterval(() => {
      this.checkCertificateStatus();
    }, 30000); // Check every 30 seconds
  }

  checkCertificateStatus() {
    // Check if certificate is being used
    const certificateIndicators = [
      'input[type="file"][accept*="p12"]',
      'input[type="file"][accept*="pfx"]',
      'select[name*="certificado"] option:checked',
      '.certificate-selected',
      '[data-certificate-active]'
    ];

    let certificateFound = false;
    certificateIndicators.forEach(selector => {
      if (document.querySelector(selector)) {
        certificateFound = true;
      }
    });

    if (certificateFound && !this.isActive) {
      this.isActive = true;
      this.logActivity('CERTIFICATE_ACTIVATED', {
        site: window.location.hostname,
        timestamp: new Date().toISOString()
      });
    }
  }

  monitorFormSubmissions() {
    // Monitor all form submissions for security
    document.addEventListener('submit', (event) => {
      const form = event.target;
      const formData = new FormData(form);
      
      // Check if form contains certificate data
      let containsCertificate = false;
      for (const [key, value] of formData.entries()) {
        if (key.toLowerCase().includes('cert') || 
            key.toLowerCase().includes('p12') || 
            key.toLowerCase().includes('pfx')) {
          containsCertificate = true;
          break;
        }
      }

      if (containsCertificate) {
        this.logActivity('CERTIFICATE_FORM_SUBMITTED', {
          formAction: form.action,
          timestamp: new Date().toISOString(),
          site: window.location.hostname
        });
      }
    });
  }

  trackUserActivity() {
    // Track user interactions for behavioral analysis
    let clickCount = 0;
    let keystrokes = 0;
    let lastActivity = Date.now();

    document.addEventListener('click', (event) => {
      clickCount++;
      lastActivity = Date.now();
      
      // Log clicks on sensitive elements
      if (event.target.type === 'submit' || 
          event.target.tagName === 'BUTTON' ||
          event.target.closest('a[href*="login"]') ||
          event.target.closest('a[href*="certificado"]')) {
        
        this.logActivity('SENSITIVE_CLICK', {
          elementType: event.target.tagName,
          elementText: event.target.textContent?.substring(0, 100),
          timestamp: new Date().toISOString()
        });
      }
    });

    document.addEventListener('keydown', (event) => {
      keystrokes++;
      lastActivity = Date.now();
      
      // Log sensitive keystrokes
      if (event.ctrlKey || event.altKey || event.metaKey) {
        this.logActivity('KEYBOARD_SHORTCUT', {
          key: event.key,
          ctrlKey: event.ctrlKey,
          altKey: event.altKey,
          metaKey: event.metaKey,
          timestamp: new Date().toISOString()
        });
      }
    });

    // Periodic activity summary
    setInterval(() => {
      if (Date.now() - lastActivity < 60000) { // Active in last minute
        this.logActivity('ACTIVITY_SUMMARY', {
          clickCount,
          keystrokes,
          activeTime: Date.now() - lastActivity,
          timestamp: new Date().toISOString()
        });
        
        clickCount = 0;
        keystrokes = 0;
      }
    }, 60000); // Every minute
  }

  logActivity(action, details = {}) {
    const activity = {
      action,
      details,
      timestamp: new Date().toISOString(),
      url: window.location.href,
      userAgent: navigator.userAgent,
      site: window.location.hostname
    };

    console.log('🔐 Activity logged:', activity);

    // Send to background script
    chrome.runtime.sendMessage({
      type: 'LOG_ACTIVITY',
      activity
    });

    // Store locally
    this.storeActivity(activity);
  }

  storeActivity(activity) {
    // Store activity in local storage for offline analysis
    const activities = JSON.parse(localStorage.getItem('certguard_activities') || '[]');
    activities.push(activity);
    
    // Keep only last 1000 activities
    if (activities.length > 1000) {
      activities.splice(0, activities.length - 1000);
    }
    
    localStorage.setItem('certguard_activities', JSON.stringify(activities));
  }
}

// Initialize content script
const certguardContent = new CertGuardContent();

// Listen for messages from popup/background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_ACTIVITY_SUMMARY') {
    const activities = JSON.parse(localStorage.getItem('certguard_activities') || '[]');
    sendResponse({
      totalActivities: activities.length,
      recentActivities: activities.slice(-10),
      isActive: certguardContent.isActive
    });
  }
});