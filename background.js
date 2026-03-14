// ⭐ PhishGuard Background Service Worker (Hybrid Threat Intelligence)

// ---------------------------------------
// 🔹 Local Threat Detection Heuristics
// ---------------------------------------

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

// ---------------------------------------
// 🔹 API Functions for Verified Threat Lookup
// ---------------------------------------

// 🛡️ Google Safe Browsing Check
async function checkGoogleSafeBrowsing(url) {
  const apiKey = "AIzaSyBWgNdV8MDMA0UWt2s9RINbhlmjWK6z0iE"; // Replace with your key
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

  const reqBody = {
    client: { clientId: "phishguard", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      body: JSON.stringify(reqBody)
    });
    const data = await res.json();
    return data?.matches ? true : false;
  } catch {
    return false;
  }
}

// 🐟 PhishTank Check
async function checkPhishTank(url) {
  const endpoint = `https://checkurl.phishtank.com/checkurl/?format=json&url=${encodeURIComponent(url)}`;

  try {
    const res = await fetch(endpoint);
    const data = await res.json();
    return data?.results?.in_database && data?.results?.verified;
  } catch {
    return false;
  }
}

// ---------------------------------------
// 🔹 Main URL Security Analyzer
// ---------------------------------------

async function analyzeThreat(tabId, url) {
  let result = detectThreats(url); // Local heuristics first

  // Run Verified API Threat Lookups
  const fromGoogle = await checkGoogleSafeBrowsing(url);
  const fromPhishTank = await checkPhishTank(url);

  let reason = result.reason;
  let isSuspicious = result.isSuspicious;

  if (fromGoogle) {
    isSuspicious = true;
    reason = "⚠️ Flagged by Google Safe Browsing";
  }

  if (fromPhishTank) {
    isSuspicious = true;
    reason = "🚨 Verified Phishing Site by PhishTank";
  }

  // Send response back to content script
  chrome.tabs.sendMessage(tabId, {
    action: "showScan",
    isSuspicious: isSuspicious,
    reason: reason,
    url: url
  }).catch(() => {});

  // Badge UI
  chrome.action.setBadgeText({ tabId, text: isSuspicious ? "!" : "✓" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: isSuspicious ? "#FF0000" : "#00AA00" });
}

// ---------------------------------------
// 🔹 Local Heuristic Detection Engine
// ---------------------------------------

function detectThreats(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const domain = hostname.replace("www.", "");

    if (KNOWN_PHISHING_DOMAINS.some(d => hostname.includes(d)))
      return { isSuspicious: true, reason: "Domain found in phishing indicators" };

    if (KNOWN_SAFE_DOMAINS.includes(domain))
      return { isSuspicious: false, reason: "Common trusted website" };

    for (const [target, variations] of Object.entries(TYPOSQUATTING_TARGETS)) {
      if (variations.some(v => hostname.includes(v)))
        return { isSuspicious: true, reason: "Detected typosquatting attempt" };
    }

    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld)))
      return { isSuspicious: true, reason: "Suspicious TLD detected (.tk .ml .ga .cf)" };

    const keywords = ["verify", "confirm", "update", "secure", "login", "account"];
    if (keywords.filter(k => url.includes(k)).length >= 2 &&
        !KNOWN_SAFE_DOMAINS.includes(domain))
      return { isSuspicious: true, reason: "Multiple phishing keywords detected" };

    if (hostname.split(".").length > 4)
      return { isSuspicious: true, reason: "Unusual domain/subdomain pattern" };

    if (url.startsWith("http://") && keywords.some(kw => url.includes(kw)))
      return { isSuspicious: true, reason: "Insecure HTTP website with sensitive text" };

    if (/^\d+\.\d+\.\d+\.\d+/.test(hostname))
      return { isSuspicious: true, reason: "Direct IP-based web hosting detected" };

    return { isSuspicious: false, reason: "No threat indicators found" };

  } catch {
    return { isSuspicious: false, reason: "Unable to confirm site security" };
  }
}

// ---------------------------------------
// 🔹 Browser Listener (Triggers Scan)
// ---------------------------------------

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url && !tab.url.startsWith("chrome://")) {
    analyzeThreat(tabId, tab.url);
  }
});
