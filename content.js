// PhishGuard Content Script - Runs detection immediately on page load

const KNOWN_PHISHING_DOMAINS = [
  "unsafe", "phishing", "login-verify", "free-crypto", "account-update",
  "test-site", "bank-of-america-secure", "paypal-verify", "apple-id-verify",
  "amazon-update", "google-security-check", "microsoft-account-verify"
];

const KNOWN_SAFE_DOMAINS = [
  "google.com", "facebook.com", "github.com", "amazon.com", "microsoft.com",
  "apple.com", "youtube.com", "stackoverflow.com", "wikipedia.org", "replit.com"
];

const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf"];

const TYPOSQUATTING_TARGETS = {
  "google": ["gooogle", "goolge", "googel"],
  "facebook": ["facbook", "facebok"],
  "amazon": ["amazn", "amzon"],
  "paypal": ["paypall", "paypa1"],
  "apple": ["appla", "aple"]
};

// Detect threats immediately
function detectThreats(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const domain = hostname.replace('www.', '');
    
    // 1. Check Known Phishing Database
    if (KNOWN_PHISHING_DOMAINS.some(d => hostname.includes(d))) {
      return { isSuspicious: true, reason: "Domain found in phishing database" };
    }

    // 2. Check if it's a known safe domain
    if (KNOWN_SAFE_DOMAINS.some(d => domain === d || hostname === d)) {
      return { isSuspicious: false, reason: "Verified safe domain" };
    }

    // 3. Detect Typosquatting
    for (const [target, variations] of Object.entries(TYPOSQUATTING_TARGETS)) {
      for (const variation of variations) {
        if (hostname.includes(variation)) {
          return { isSuspicious: true, reason: "Possible typosquatting attack" };
        }
      }
    }

    // 4. Check for suspicious TLDs
    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
      return { isSuspicious: true, reason: "Suspicious domain extension (.tk, .ml, .ga, .cf)" };
    }

    // 5. Check for suspicious keywords in URL
    const suspiciousKeywords = ["verify", "confirm", "update", "secure", "login", "account"];
    const hasMultipleSuspiciousKeywords = suspiciousKeywords.filter(keyword => url.includes(keyword)).length >= 2;
    if (hasMultipleSuspiciousKeywords && !KNOWN_SAFE_DOMAINS.some(d => domain === d)) {
      return { isSuspicious: true, reason: "Multiple suspicious keywords detected" };
    }

    // 6. Check for suspicious subdomain structure
    const subdomainLevels = hostname.split('.').length;
    if (subdomainLevels > 4) {
      return { isSuspicious: true, reason: "Unusual domain structure detected" };
    }

    // 7. Check if HTTP without SSL on sensitive keywords
    if (url.startsWith('http://') && suspiciousKeywords.some(kw => url.includes(kw))) {
      return { isSuspicious: true, reason: "Insecure connection on sensitive content" };
    }

    // 8. Check for IP address instead of domain
    if (/^\d+\.\d+\.\d+\.\d+/.test(hostname)) {
      return { isSuspicious: true, reason: "Direct IP access detected" };
    }

    return { isSuspicious: false, reason: "Site passed all security checks" };
  } catch (error) {
    return { isSuspicious: false, reason: "Unable to analyze" };
  }
}

// Show scan popup
function showAutoScan(isSuspicious, reason, url) {
  // Remove previous scanner if exists
  const existing = document.getElementById('phishguard-scanner');
  if (existing) existing.remove();

  // Create overlay
  const overlay = document.createElement('div');
  overlay.id = 'phishguard-scanner';
  
  // Add styles
  const style = document.createElement('style');
  style.textContent = `
    #phishguard-scanner {
      all: initial;
      position: fixed;
      top: 20px;
      right: 20px;
      width: 320px;
      background: rgba(15, 23, 42, 0.98);
      color: white;
      z-index: 2147483647;
      border-radius: 12px;
      border: 2px solid #22d3ee;
      box-shadow: 0 0 30px rgba(34, 211, 238, 0.4);
      font-family: 'Segoe UI', sans-serif;
      backdrop-filter: blur(10px);
      overflow: hidden;
      animation: pg-slide-in 0.4s ease-out;
    }

    @keyframes pg-slide-in {
      from { 
        opacity: 0; 
        transform: translateY(-30px); 
      }
      to { 
        opacity: 1; 
        transform: translateY(0); 
      }
    }

    #phishguard-scanner .pg-scan-container {
      padding: 20px;
      box-sizing: border-box;
    }

    #phishguard-scanner .pg-logo {
      color: #22d3ee;
      font-weight: bold;
      font-size: 13px;
      letter-spacing: 1px;
      margin-bottom: 12px;
      display: block;
    }

    #phishguard-scanner .pg-status {
      font-size: 18px;
      font-weight: 700;
      margin-bottom: 8px;
      display: block;
    }

    #phishguard-scanner .pg-reason {
      font-size: 12px;
      color: #cbd5e1;
      margin-bottom: 12px;
      line-height: 1.5;
      display: block;
    }

    #phishguard-scanner .pg-progress-bg {
      width: 100%;
      height: 3px;
      background: #334155;
      border-radius: 2px;
      margin-bottom: 12px;
      overflow: hidden;
      box-sizing: border-box;
    }

    #phishguard-scanner .pg-progress-bar {
      width: 0%;
      height: 100%;
      background: #22d3ee;
      transition: width 0.3s ease;
      box-shadow: 0 0 10px #22d3ee;
    }

    #phishguard-scanner.pg-secure {
      border-color: #10b981;
      box-shadow: 0 0 30px rgba(16, 185, 129, 0.4);
    }

    #phishguard-scanner.pg-secure .pg-logo { color: #10b981; }
    #phishguard-scanner.pg-secure .pg-progress-bar { background: #10b981; box-shadow: 0 0 10px #10b981; width: 100% !important; }
    
    #phishguard-scanner.pg-danger {
      border-color: #ef4444;
      box-shadow: 0 0 30px rgba(239, 68, 68, 0.4);
    }

    #phishguard-scanner.pg-danger .pg-logo { color: #ef4444; }
    #phishguard-scanner.pg-danger .pg-progress-bar { background: #ef4444; box-shadow: 0 0 10px #ef4444; width: 100% !important; }

    #phishguard-scanner .pg-buttons {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }

    #phishguard-scanner .pg-btn {
      flex: 1;
      padding: 10px;
      border: none;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
      box-sizing: border-box;
    }

    #phishguard-scanner .pg-btn-primary {
      background: #22d3ee;
      color: #0f172a;
    }

    #phishguard-scanner .pg-btn-primary:hover {
      background: #06b6d4;
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(34, 211, 238, 0.3);
    }

    #phishguard-scanner .pg-btn-secondary {
      background: #ef4444;
      color: white;
    }

    #phishguard-scanner .pg-btn-secondary:hover {
      background: #dc2626;
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
    }

    #phishguard-scanner .pg-btn-safe {
      background: #10b981;
      color: white;
    }

    #phishguard-scanner .pg-btn-safe:hover {
      background: #059669;
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
    }
  `;

  document.head.appendChild(style);

  if (isSuspicious) {
    overlay.innerHTML = `
      <div class="pg-scan-container">
        <div class="pg-logo">🛡️ PHISHGUARD</div>
        <div class="pg-status" style="color: #ef4444;">⚠️ THREAT DETECTED</div>
        <div class="pg-reason">${reason}</div>
        <div class="pg-progress-bg">
          <div class="pg-progress-bar" style="width: 100%;"></div>
        </div>
        <div class="pg-buttons">
          <button class="pg-btn pg-btn-safe" onclick="history.back();">← Back to Safety</button>
          <button class="pg-btn pg-btn-secondary" onclick="document.getElementById('phishguard-scanner').remove();">Proceed Anyway</button>
        </div>
      </div>
    `;
    overlay.classList.add('pg-danger');
  } else {
    overlay.innerHTML = `
      <div class="pg-scan-container">
        <div class="pg-logo">🛡️ PHISHGUARD</div>
        <div class="pg-status" style="color: #10b981;">✅ Site Secure</div>
        <div class="pg-reason">${reason}</div>
        <div class="pg-progress-bg">
          <div class="pg-progress-bar" style="width: 100%;"></div>
        </div>
      </div>
    `;
    overlay.classList.add('pg-secure');
    
    // Auto-hide safe notification
    setTimeout(() => {
      if (document.body && document.body.contains(overlay)) {
        overlay.style.opacity = '0';
        overlay.style.transform = 'translateY(-30px)';
        setTimeout(() => {
          if (document.body.contains(overlay)) overlay.remove();
        }, 300);
      }
    }, 3000);
  }

  document.body.appendChild(overlay);
}

// Run detection on page load
function initialize() {
  const url = window.location.href;
  const result = detectThreats(url);
  showAutoScan(result.isSuspicious, result.reason, url);
  console.log("PhishGuard: Scan complete -", result);
}

// Wait for DOM to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initialize);
} else {
  initialize();
}
