// CertGuard AI - Background Script
class CertGuardBackground {
  constructor() {
    this.API_BASE = 'https://4467813a-53fb-447d-a535-d1c3afcb1b4e.preview.emergentagent.com/api';
    this.activities = [];
    this.isMonitoring = false;
    this.init();
  }

  init() {
    console.log('🔐 CertGuard AI - Background Script Initialized');
    
    // Set up event listeners
    this.setupEventListeners();
    
    // Start monitoring
    this.startMonitoring();
    
    // Initialize extension icon
    this.updateIcon('inactive');
  }

  setupEventListeners() {
    // Listen for tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url) {
        this.onTabUpdated(tabId, tab);
      }
    });

    // Listen for tab activation
    chrome.tabs.onActivated.addListener((activeInfo) => {
      chrome.tabs.get(activeInfo.tabId, (tab) => {
        this.onTabActivated(tab);
      });
    });

    // Listen for messages from content scripts
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse);
    });

    // Listen for web navigation
    chrome.webNavigation.onCompleted.addListener((details) => {
      if (details.frameId === 0) { // Main frame only
        this.onNavigationCompleted(details);
      }
    });

    // Listen for extension installation
    chrome.runtime.onInstalled.addListener(() => {
      this.onExtensionInstalled();
    });
  }

  onTabUpdated(tabId, tab) {
    if (this.isSupportedSite(tab.url)) {
      console.log('🔐 Supported site detected:', tab.url);
      this.updateIcon('active');
      this.logActivity('SITE_VISITED', {
        tabId,
        url: tab.url,
        title: tab.title,
        timestamp: new Date().toISOString()
      });
    } else {
      this.updateIcon('inactive');
    }
  }

  onTabActivated(tab) {
    if (tab && this.isSupportedSite(tab.url)) {
      this.updateIcon('active');
    } else {
      this.updateIcon('inactive');
    }
  }

  onNavigationCompleted(details) {
    if (this.isSupportedSite(details.url)) {
      this.logActivity('NAVIGATION_COMPLETED', {
        tabId: details.tabId,
        url: details.url,
        timestamp: new Date().toISOString()
      });
    }
  }

  onExtensionInstalled() {
    console.log('🔐 CertGuard AI Extension Installed');
    
    // Create welcome notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'CertGuard AI',
      message: 'Extensão instalada com sucesso! Proteção de certificados ativada.'
    });

    // Open welcome page
    chrome.tabs.create({
      url: 'https://4467813a-53fb-447d-a535-d1c3afcb1b4e.preview.emergentagent.com'
    });
  }

  isSupportedSite(url) {
    if (!url) return false;
    
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

    return supportedDomains.some(domain => url.includes(domain));
  }

  updateIcon(status) {
    const iconPath = status === 'active' ? 'icons/icon-active.png' : 'icons/icon48.png';
    const badgeColor = status === 'active' ? '#28a745' : '#dc3545';
    const badgeText = status === 'active' ? '●' : '';

    chrome.action.setIcon({ path: iconPath });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor });
    chrome.action.setBadgeText({ text: badgeText });
  }

  handleMessage(request, sender, sendResponse) {
    console.log('🔐 Message received:', request.type);

    switch (request.type) {
      case 'LOG_ACTIVITY':
        this.logActivity(request.activity.action, request.activity.details, sender.tab);
        sendResponse({ success: true });
        break;

      case 'GET_ACTIVITIES':
        sendResponse({ activities: this.activities.slice(-50) });
        break;

      case 'CLEAR_ACTIVITIES':
        this.activities = [];
        sendResponse({ success: true });
        break;

      case 'GET_STATUS':
        sendResponse({
          isMonitoring: this.isMonitoring,
          activityCount: this.activities.length,
          supportedSite: sender.tab ? this.isSupportedSite(sender.tab.url) : false
        });
        break;

      case 'TOGGLE_MONITORING':
        this.isMonitoring = !this.isMonitoring;
        sendResponse({ isMonitoring: this.isMonitoring });
        break;

      default:
        sendResponse({ error: 'Unknown message type' });
    }
  }

  logActivity(action, details = {}, tab = null) {
    const activity = {
      id: Date.now().toString(),
      action,
      details,
      timestamp: new Date().toISOString(),
      tabId: tab?.id,
      url: tab?.url,
      title: tab?.title
    };

    console.log('🔐 Activity logged:', activity);

    // Store activity
    this.activities.push(activity);

    // Keep only last 10000 activities
    if (this.activities.length > 10000) {
      this.activities.splice(0, this.activities.length - 10000);
    }

    // Send to backend if needed
    this.sendActivityToBackend(activity);

    // Check for security alerts
    this.checkSecurityAlerts(activity);
  }

  async sendActivityToBackend(activity) {
    try {
      // Get stored token
      const result = await chrome.storage.sync.get(['token']);
      if (!result.token) {
        console.log('🔐 No token found, skipping backend sync');
        return;
      }

      // Send to backend
      const response = await fetch(`${this.API_BASE}/audit/log`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${result.token}`
        },
        body: JSON.stringify({
          action_type: activity.action,
          details: activity.details,
          timestamp: activity.timestamp,
          url: activity.url
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      console.log('🔐 Activity sent to backend successfully');

    } catch (error) {
      console.error('🔐 Error sending activity to backend:', error);
    }
  }

  checkSecurityAlerts(activity) {
    // Check for suspicious patterns
    const recentActivities = this.activities.slice(-10);
    
    // Rapid clicking detection
    const clickActivities = recentActivities.filter(a => a.action === 'SENSITIVE_CLICK');
    if (clickActivities.length > 5) {
      this.createSecurityAlert('RAPID_CLICKING', 'Detected rapid clicking pattern', 'medium');
    }

    // Off-hours activity
    const currentHour = new Date().getHours();
    if (currentHour < 6 || currentHour > 22) {
      this.createSecurityAlert('OFF_HOURS_ACTIVITY', 'Activity detected outside business hours', 'low');
    }

    // Multiple certificate usage
    const certActivities = recentActivities.filter(a => a.action.includes('CERTIFICATE'));
    if (certActivities.length > 3) {
      this.createSecurityAlert('MULTIPLE_CERT_ACTIVITY', 'Multiple certificate-related activities', 'high');
    }
  }

  createSecurityAlert(type, message, severity) {
    const alert = {
      id: Date.now().toString(),
      type,
      message,
      severity,
      timestamp: new Date().toISOString(),
      resolved: false
    };

    console.log('🔐 Security alert created:', alert);

    // Store alert
    chrome.storage.local.get(['securityAlerts'], (result) => {
      const alerts = result.securityAlerts || [];
      alerts.push(alert);
      
      // Keep only last 100 alerts
      if (alerts.length > 100) {
        alerts.splice(0, alerts.length - 100);
      }
      
      chrome.storage.local.set({ securityAlerts: alerts });
    });

    // Show notification for high severity
    if (severity === 'high') {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'CertGuard AI - Alerta de Segurança',
        message: message
      });
    }
  }

  startMonitoring() {
    this.isMonitoring = true;
    console.log('🔐 Security monitoring started');

    // Periodic monitoring tasks
    setInterval(() => {
      this.performPeriodicChecks();
    }, 60000); // Every minute

    // Cleanup old activities
    setInterval(() => {
      this.cleanupOldActivities();
    }, 3600000); // Every hour
  }

  performPeriodicChecks() {
    if (!this.isMonitoring) return;

    // Check for inactive sessions
    const lastActivity = this.activities.slice(-1)[0];
    if (lastActivity) {
      const timeSinceLastActivity = Date.now() - new Date(lastActivity.timestamp).getTime();
      if (timeSinceLastActivity > 1800000) { // 30 minutes
        this.logActivity('SESSION_INACTIVE', {
          timeSinceLastActivity,
          timestamp: new Date().toISOString()
        });
      }
    }

    // Update activity statistics
    this.updateActivityStatistics();
  }

  updateActivityStatistics() {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 3600000);
    
    const recentActivities = this.activities.filter(
      activity => new Date(activity.timestamp) > oneHourAgo
    );

    const stats = {
      totalActivities: this.activities.length,
      recentActivities: recentActivities.length,
      lastUpdate: now.toISOString()
    };

    chrome.storage.local.set({ activityStats: stats });
  }

  cleanupOldActivities() {
    const oneDayAgo = new Date();
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);

    const filteredActivities = this.activities.filter(
      activity => new Date(activity.timestamp) > oneDayAgo
    );

    this.activities = filteredActivities;
    console.log(`🔐 Cleaned up old activities. Current count: ${this.activities.length}`);
  }
}

// Initialize background script
const certguardBackground = new CertGuardBackground();