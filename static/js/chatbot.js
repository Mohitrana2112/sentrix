/**
 * SENTRIX AI Assistant Client
 * Floating drawer, markdown rendering, typing indicator, prompt chips, real backend API connection.
 */

document.addEventListener('DOMContentLoaded', () => {
  const launcherBtn = document.getElementById('chatbotLauncherBtn');
  const chatWindow = document.getElementById('chatbotWindow');
  const closeBtn = document.getElementById('closeChatbotBtn');
  const clearBtn = document.getElementById('clearChatbotBtn');
  const chatBody = document.getElementById('chatbotBody');
  const chatInput = document.getElementById('chatbotInput');
  const sendBtn = document.getElementById('chatbotSendBtn');
  const promptPills = document.querySelectorAll('.prompt-pill');

  let isSending = false;

  // Toggle Chatbot Window
  function toggleChatbot() {
    if (!chatWindow) return;
    chatWindow.classList.toggle('open');
    if (chatWindow.classList.contains('open') && chatInput) {
      setTimeout(() => chatInput.focus(), 150);
      scrollToBottom();
    }
  }

  if (launcherBtn) launcherBtn.addEventListener('click', toggleChatbot);
  if (closeBtn) closeBtn.addEventListener('click', toggleChatbot);

  // Clear Chat History
  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      if (confirm('Clear current investigation conversation?')) {
        try {
          await fetch('/api/chatbot/clear', { method: 'POST' });
        } catch (e) {}
        if (chatBody) {
          chatBody.innerHTML = `
            <div class="chat-msg assistant">
              <div class="chat-bubble">
                <strong>SENTRIX AI</strong> online. Conversation reset. How may I assist your security investigation?
              </div>
            </div>
          `;
        }
      }
    });
  }

  // Quick Prompt Pills
  promptPills.forEach(pill => {
    pill.addEventListener('click', () => {
      const promptText = pill.getAttribute('data-prompt') || pill.textContent.trim();
      if (chatInput) {
        chatInput.value = promptText;
        sendMessage();
      }
    });
  });

  // Send message on Enter or click
  if (chatInput) {
    chatInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });
  }

  if (sendBtn) {
    sendBtn.addEventListener('click', sendMessage);
  }

  async function sendMessage() {
    if (isSending || !chatInput) return;
    const msg = chatInput.value.trim();
    if (!msg) return;

    chatInput.value = '';
    isSending = true;

    // 1. Append User Message
    appendMessage('user', msg);

    // 2. Append Typing Indicator
    const typingId = 'typingIndicator_' + Date.now();
    appendTypingIndicator(typingId);
    scrollToBottom();

    // Context URL and telemetry data if on an investigation page or after live scan
    const urlParams = new URLSearchParams(window.location.search);
    const contextUrl = urlParams.get('url') || urlParams.get('domain') || (window.currentAnalysisContext ? window.currentAnalysisContext.url : null);
    const contextData = window.currentAnalysisContext || window.lastAnalyzedResult || window.lastHomepageAnalysisResult || null;

    try {
      const response = await fetch('/api/chatbot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: msg,
          context_url: contextUrl,
          context_data: contextData
        })
      });

      const data = await response.json();
      removeTypingIndicator(typingId);

      if (data.success && data.reply) {
        appendMessage('assistant', data.reply);
      } else {
        appendMessage('assistant', `⚠️ ${data.error || 'Unable to process inquiry. Please verify network or API keys in Settings.'}`);
      }
    } catch (err) {
      removeTypingIndicator(typingId);
      appendMessage('assistant', '⚠️ Connection timeout communicating with SENTRIX AI engine.');
      console.error(err);
    } finally {
      isSending = false;
      scrollToBottom();
    }
  }

  function appendMessage(sender, text) {
    if (!chatBody) return;
    const msgElem = document.createElement('div');
    msgElem.className = `chat-msg ${sender}`;

    // Format simple markdown into HTML
    const formatted = formatMarkdown(text);

    if (sender === 'assistant') {
      msgElem.innerHTML = `
        <div class="chat-bubble">
          ${formatted}
          <div style="margin-top:0.4rem; display:flex; justify-content:flex-end;">
            <button class="btn btn-sm btn-secondary copy-chat-btn" style="padding:2px 6px; font-size:0.68rem;" title="Copy response">
              <i data-lucide="copy" style="width:12px;height:12px;"></i> Copy
            </button>
          </div>
        </div>
      `;
      // Attach copy handler
      const copyBtn = msgElem.querySelector('.copy-chat-btn');
      if (copyBtn) {
        copyBtn.addEventListener('click', () => {
          window.copyToClipboard(text, copyBtn);
        });
      }
    } else {
      msgElem.innerHTML = `
        <div class="chat-bubble">
          ${escapeHtml(text)}
        </div>
      `;
    }

    chatBody.appendChild(msgElem);
    if (window.lucide) lucide.createIcons();
    scrollToBottom();
  }

  function appendTypingIndicator(id) {
    if (!chatBody) return;
    const elem = document.createElement('div');
    elem.id = id;
    elem.className = 'chat-msg assistant';
    elem.innerHTML = `
      <div class="chat-bubble" style="display:flex; align-items:center; gap:5px; padding:0.6rem 0.9rem;">
        <span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:var(--cyan-electric); animation:pulseDots 1s infinite alternate;"></span>
        <span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:var(--cyan-electric); animation:pulseDots 1s infinite 0.2s alternate;"></span>
        <span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:var(--cyan-electric); animation:pulseDots 1s infinite 0.4s alternate;"></span>
      </div>
    `;
    chatBody.appendChild(elem);
  }

  function removeTypingIndicator(id) {
    const elem = document.getElementById(id);
    if (elem) elem.remove();
  }

  function scrollToBottom() {
    if (chatBody) {
      chatBody.scrollTop = chatBody.scrollHeight;
    }
  }

  function escapeHtml(string) {
    const entityMap = {
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '/': '&#x2F;'
    };
    return String(string).replace(/[&<>"'\/]/g, s => entityMap[s]);
  }

  function formatMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);
    // Bold
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    // Italic
    html = html.replace(/_(.*?)_/g, '<em>$1</em>');
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code style="background:var(--bg-glass-input); padding:2px 5px; border-radius:4px; font-size:0.8rem; color:var(--cyan-electric);">$1</code>');
    // Bullet points
    html = html.replace(/^\s*-\s+(.+)$/gm, '<li style="margin-left:1.2rem; margin-bottom:0.25rem;">$1</li>');
    // Headers
    html = html.replace(/^### (.*$)/gm, '<h5 style="color:var(--cyan-electric); margin-top:0.6rem; margin-bottom:0.3rem;">$1</h5>');
    html = html.replace(/^#### (.*$)/gm, '<h6 style="color:var(--text-main); margin-top:0.4rem; margin-bottom:0.2rem; font-weight:700;">$1</h6>');
    // Line breaks
    html = html.replace(/\n\n/g, '<p style="margin-bottom:0.5rem;"></p>');
    html = html.replace(/\n/g, '<br/>');
    return html;
  }

  // Global helper to open chatbot with contextual prompt
  window.openSentrixChatWithPrompt = function(promptText) {
    if (chatWindow && !chatWindow.classList.contains('open')) {
      toggleChatbot();
    }
    if (chatInput) {
      chatInput.value = promptText;
      sendMessage();
    }
  };
});
