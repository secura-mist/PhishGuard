document.addEventListener('DOMContentLoaded', function() {
  // Get current tab URL
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    const url = tabs[0].url;
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const statusDesc = document.getElementById('status-desc');
    
    if (url.includes('unsafe') || url.includes('phishing')) {
      statusIcon.className = 'status-indicator danger';
      statusIcon.innerHTML = '!';
      statusText.innerText = 'Phishing Detected';
      statusText.style.color = '#ef4444';
      statusDesc.innerText = 'This site matches known threat patterns.';
    }
  });

  document.getElementById('scan-btn').addEventListener('click', () => {
    const btn = document.getElementById('scan-btn');
    btn.innerText = 'Scanning...';
    setTimeout(() => {
      btn.innerText = 'Scan Complete - No Issues';
    }, 1500);
  });

  document.getElementById('test-btn').addEventListener('click', () => {
    // Open a test URL that triggers the block
    chrome.tabs.create({ url: 'http://unsafe-test-site.com' });
  });
});
