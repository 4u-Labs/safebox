// SafePass Content Script - AutoFill Engine

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function isExtensionValid() {
  try {
    return !!(typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id);
  } catch (e) {
    return false;
  }
}

if (isExtensionValid()) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'autofill') {
      const success = performAutoFill(request.username, request.password);
      sendResponse({ success });
    } else if (request.action === 'get_vault') {
      const vault = localStorage.getItem('safepass_encrypted_vault');
      const token = localStorage.getItem('safepass_cloud_token');
      const user = localStorage.getItem('safepass_cloud_user');
      sendResponse({ success: true, vault, token, user });
    } else if (request.action === 'direct_inject_pending') {
      if (request.item) {
        window.dispatchEvent(new CustomEvent('safepass_inject_pending', { detail: [request.item] }));
        sendResponse({ success: true });
      }
    } else if (request.action === 'direct_inject_full_vault') {
      if (request.vault_data) {
        window.dispatchEvent(new CustomEvent('safepass_inject_full_vault', { detail: { vault_data: request.vault_data } }));
        sendResponse({ success: true });
      }
    } else if (request.action === 'query_matches') {
      const domain = (request.domain || '').toLowerCase();
      const onReply = (e) => {
        window.removeEventListener('safepass_query_matches_reply', onReply);
        sendResponse({ logins: (e.detail && e.detail.logins) ? e.detail.logins : [] });
      };
      window.addEventListener('safepass_query_matches_reply', onReply);
      window.dispatchEvent(new CustomEvent('safepass_query_matches', { detail: { domain } }));
      setTimeout(() => {
        window.removeEventListener('safepass_query_matches_reply', onReply);
      }, 400);
      return true;
    }
    return true;
  });
}

function performAutoFill(username, password) {
  let filledPass = false;
  let filledUser = false;

  // 1. Preencher campo de senha
  let passInput = document.querySelector('input#pass, input[name="pass"], input[data-testid="royal_pass"]');
  if (!passInput) {
    const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]')).filter(el => {
      return el.offsetParent !== null && !el.disabled && !el.readOnly;
    });
    if (passwordInputs.length > 0) passInput = passwordInputs[0];
  }

  if (passInput && password) {
    setNativeValue(passInput, password);
    filledPass = true;
  }

  // 2. Preencher campo de usuário / email
  if (username) {
    let userInput = document.querySelector('input#email, input[name="email"], input[data-testid="royal_email"]');
    if (!userInput) {
      const allInputs = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="password"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])')).filter(el => el.offsetParent !== null && !el.disabled && !el.readOnly);

      userInput = allInputs.find(i => {
        const attr = ((i.name || '') + ' ' + (i.id || '') + ' ' + (i.placeholder || '') + ' ' + (i.getAttribute('aria-label') || '') + ' ' + (i.getAttribute('autocomplete') || '')).toLowerCase();
        return attr.includes('email') || attr.includes('user') || attr.includes('login') || attr.includes('usuario') || attr.includes('ident') || attr.includes('phone') || attr.includes('tel') || i.type === 'email' || i.type === 'tel';
      });

      if (!userInput && allInputs.length > 0) {
        userInput = allInputs[0];
      }
    }

    if (userInput) {
      setNativeValue(userInput, username);
      filledUser = true;
    }
  }

  return filledPass || filledUser;
}

// Disparar eventos nativos para que React, Vue e Angular detectem a alteração
function setNativeValue(element, value) {
  element.focus();
  const valueSetter = Object.getOwnPropertyDescriptor(element, 'value') ? 
                      Object.getOwnPropertyDescriptor(element, 'value').set : null;
  const prototype = Object.getPrototypeOf(element);
  const prototypeValueSetter = Object.getOwnPropertyDescriptor(prototype, 'value') ? 
                               Object.getOwnPropertyDescriptor(prototype, 'value').set : null;

  if (prototypeValueSetter && valueSetter !== prototypeValueSetter) {
    prototypeValueSetter.call(element, value);
  } else if (valueSetter) {
    valueSetter.call(element, value);
  } else {
    element.value = value;
  }

  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
  element.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'a' }));
  element.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'a' }));
}

// ── 3. SINCRONIZAÇÃO AUTOMÁTICA COM O WEBAPP (APENAS NA ROTA /SAFEPASS OU /SAFEBOX) ──
const isSafePassWebPage = (window.location.pathname.includes('/safepass') || window.location.pathname.includes('/safebox'));

if (isSafePassWebPage) {
  const syncFromWebApp = () => {
    if (!isExtensionValid()) return;
    try {
      const webVault = localStorage.getItem('safepass_encrypted_vault');
      const cloudToken = localStorage.getItem('safepass_cloud_token');
      const cloudUser = localStorage.getItem('safepass_cloud_user');

      if (webVault && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
          'safepass_encrypted_vault': webVault,
          'safepass_cloud_token': cloudToken || '',
          'safepass_cloud_user': cloudUser || ''
        });
      }
    } catch(e) {}
  };

  const checkAndInjectPending = () => {
    if (!isExtensionValid()) return;
    try {
      chrome.storage.local.get(['safepass_pending_vault_items'], (res) => {
        if (chrome.runtime.lastError || !isExtensionValid()) return;
        const pending = res['safepass_pending_vault_items'] || [];
        if (pending.length > 0) {
          window.dispatchEvent(new CustomEvent('safepass_inject_pending', { detail: pending }));
          chrome.storage.local.set({ 'safepass_pending_vault_items': [] });
        }
      });
    } catch(e) {}
  };

  // Sincroniza ao carregar a página e em qualquer alteração de dados
  syncFromWebApp();
  checkAndInjectPending();
  const pollInterval = setInterval(() => {
    if (!isExtensionValid()) {
      clearInterval(pollInterval);
      return;
    }
    checkAndInjectPending();
  }, 2000);

  window.addEventListener('storage', syncFromWebApp);
  window.addEventListener('safepass_vault_updated', syncFromWebApp);
  window.addEventListener('safepass_sync_cache', (e) => {
    if (!isExtensionValid()) return;
    try {
      if (e.detail && Array.isArray(e.detail.vault) && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ 'safepass_unlocked_vault_cache': e.detail.vault });
      }
    } catch(e) {}
  });
}

// ── 4. DETECTOR AUTOMÁTICO DE LOGIN & PROMPT PARA SALVAR SENHA ──
(function setupPasswordCapture() {
  // Ignora se estiver no próprio SafePass Web
  if (isSafePassWebPage) {
    return;
  }

  let sessionUsername = '';
  let sessionPassword = '';
  let lastCaptured = null;

  function findUsernameField(form, passwordInput) {
    if (sessionUsername && sessionUsername.length >= 3) return sessionUsername;

    const root = form || document;
    const inputs = Array.from(root.querySelectorAll('input:not([type="hidden"]):not([type="password"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])')).filter(el => el.offsetParent !== null && !el.disabled);
    
    let userInput = inputs.find(i => {
      const name = ((i.name || '') + ' ' + (i.id || '') + ' ' + (i.placeholder || '') + ' ' + (i.getAttribute('autocomplete') || '') + ' ' + (i.getAttribute('data-qa') || '')).toLowerCase();
      return name.includes('user') || name.includes('login') || name.includes('email') || name.includes('usuario') || name.includes('ident') || name.includes('phone') || i.type === 'email' || i.type === 'tel';
    });

    if (userInput && userInput.value && userInput.value.trim()) {
      return userInput.value.trim();
    }

    if (!userInput && inputs.length > 0 && inputs[0].value.trim()) {
      return inputs[0].value.trim();
    }

    // Busca por identificadores de usuário na página se for login de campo único
    const userBadge = document.querySelector('[data-user], .user-name, .username, #username, .admin-user');
    if (userBadge && userBadge.textContent.trim()) {
      return userBadge.textContent.trim();
    }

    return sessionUsername || 'admin';
  }

  function extractCleanServiceName(urlStr, rawTitle) {
    try {
      const u = new URL(urlStr || window.location.href);
      const host = u.hostname.replace(/^www\./i, '').toLowerCase();

      const brandMap = {
        '4u.ia.br': '4u.ia.br',
        'paramountplus.com': 'Paramount+',
        'disneyplus.com': 'Disney+',
        'max.com': 'Max (HBO)',
        'hbomax.com': 'Max (HBO)',
        'primevideo.com': 'Prime Video',
        'globoplay.globo.com': 'Globoplay',
        'starplus.com': 'Star+',
        'facebook.com': 'Facebook',
        'instagram.com': 'Instagram',
        'google.com': 'Google',
        'accounts.google.com': 'Google',
        'github.com': 'GitHub',
        'netflix.com': 'Netflix',
        'twitter.com': 'X (Twitter)',
        'x.com': 'X (Twitter)',
        'amazon.com': 'Amazon',
        'amazon.com.br': 'Amazon',
        'mercadolivre.com.br': 'Mercado Livre',
        'mercadolibre.com': 'Mercado Libre',
        'hostinger.com': 'Hostinger',
        'hostinger.com.br': 'Hostinger',
        'youtube.com': 'YouTube',
        'linkedin.com': 'LinkedIn',
        'microsoft.com': 'Microsoft',
        'live.com': 'Microsoft',
        'outlook.com': 'Outlook',
        'spotify.com': 'Spotify',
        'apple.com': 'Apple',
        'icloud.com': 'iCloud',
        'nubank.com.br': 'Nubank',
        'inter.co': 'Banco Inter',
        'itau.com.br': 'Itaú',
        'bradesco.com.br': 'Bradesco',
        'santander.com.br': 'Santander',
        'caixa.gov.br': 'Caixa',
        'gov.br': 'Gov.br',
        'globo.com': 'Globo',
        'discord.com': 'Discord',
        'tiktok.com': 'TikTok',
        'twitch.tv': 'Twitch',
        'reddit.com': 'Reddit',
        'chatgpt.com': 'ChatGPT',
        'openai.com': 'OpenAI'
      };

      for (const [domain, brand] of Object.entries(brandMap)) {
        if (host === domain || host.endsWith('.' + domain)) {
          return brand;
        }
      }

      if (rawTitle && rawTitle.trim()) {
        const parts = rawTitle.split(/[|\-—•:]/).map(p => p.trim()).filter(Boolean);
        for (const part of [...parts.slice(-1), ...parts.slice(0, 1)]) {
          if (part.length >= 2 && part.length <= 25 && !part.toLowerCase().includes('login') && !part.toLowerCase().includes('entrar')) {
            const hostClean = host.split('.')[0];
            if (part.toLowerCase().includes(hostClean) || hostClean.includes(part.toLowerCase())) {
              return part;
            }
          }
        }
      }

      const baseName = host.split('.')[0];
      return baseName.charAt(0).toUpperCase() + baseName.slice(1);
    } catch(e) {
      return 'Login Web';
    }
  }

  let typeTimeout = null;
  const dismissedSet = new Set();

  // 1. Monitora digitação contínua para capturar etapas de login e novas senhas digitadas
  document.addEventListener('input', (e) => {
    const target = e.target;
    if (!target || !target.value) return;

    if (target.type === 'password') {
      sessionPassword = target.value;
      if (sessionPassword.length >= 3) {
        clearTimeout(typeTimeout);
        typeTimeout = setTimeout(() => {
          if (!dismissedSet.has(sessionPassword)) {
            triggerCapture(target.closest('form'), target);
          }
        }, 700);
      }
    } else if (target.type === 'email' || target.type === 'text' || target.type === 'tel') {
      const val = target.value.trim();
      if (val.includes('@') || val.length >= 3) {
        sessionUsername = val;
      }
    }
  }, true);

  // 2. Ao sair do campo de senha (blur), dispara o prompt
  document.addEventListener('blur', (e) => {
    const target = e.target;
    if (target && target.type === 'password' && target.value && target.value.length >= 3) {
      if (!dismissedSet.has(target.value)) {
        triggerCapture(target.closest('form'), target);
      }
    }
  }, true);

  function triggerCapture(form, passwordInput) {
    let passVal = (passwordInput && passwordInput.value) ? passwordInput.value : sessionPassword;
    if (!passVal || passVal.length < 3) return;

    const username = findUsernameField(form, passwordInput);
    const cleanTitle = extractCleanServiceName(window.location.href, document.title);

    const cred = {
      username: username || sessionUsername || 'admin',
      password: passVal,
      url: window.location.href,
      domain: window.location.hostname.replace(/^www\./i, ''),
      title: cleanTitle
    };

    lastCaptured = cred;

    // Salva no storage de prompt pendente caso a página navegue para outra URL
    if (isExtensionValid()) {
      chrome.storage.local.set({ 'safepass_pending_prompt': { ...cred, timestamp: Date.now() } });
    }

    showSavePasswordPrompt(cred);
  }

  // 3. Escuta submit de formulários
  document.addEventListener('submit', (e) => {
    const form = e.target;
    const pass = (form && form.querySelector) ? form.querySelector('input[type="password"]') : null;
    triggerCapture(form, pass);
  }, true);

  // 4. Escuta cliques em qualquer botão de ação/login
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button, input[type="submit"], input[type="button"], a, [role="button"], [data-qa*="btn"], [data-qa*="button"], [data-qa*="signin"]');
    if (!btn) return;

    const pass = document.querySelector('input[type="password"]');
    if (pass && pass.value && pass.value.length >= 3) {
      const form = btn.closest('form');
      triggerCapture(form, pass);
    } else if (sessionPassword && sessionPassword.length >= 3) {
      triggerCapture(null, null);
    }
  }, true);

  // 5. Escuta tecla Enter nos inputs
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const pass = document.querySelector('input[type="password"]');
      if (pass && pass.value && pass.value.length >= 3) {
        triggerCapture(e.target.closest('form'), pass);
      } else if (sessionPassword && sessionPassword.length >= 3) {
        triggerCapture(null, null);
      }
    }
  }, true);

  // 6. Monitora transições em Single Page Apps (SPA)
  window.addEventListener('hashchange', () => {
    if (lastCaptured && lastCaptured.password && !dismissedSet.has(lastCaptured.password)) {
      setTimeout(() => showSavePasswordPrompt(lastCaptured), 400);
    }
  });

  // 7. Verifica se há prompt pendente após redirecionamento de login
  if (isExtensionValid()) {
    chrome.storage.local.get(['safepass_pending_prompt'], (res) => {
      if (chrome.runtime.lastError || !isExtensionValid()) return;
      const p = res['safepass_pending_prompt'];
      if (p && p.password && (Date.now() - p.timestamp < 30000)) {
        const curDomain = window.location.hostname.replace(/^www\./i, '').toLowerCase();
        if (p.domain && (curDomain.includes(p.domain) || p.domain.includes(curDomain))) {
          chrome.storage.local.remove('safepass_pending_prompt');
          setTimeout(() => showSavePasswordPrompt(p), 600);
        }
      }
    });
  }

  // Renderiza o Banner Flutuante de Salvar Senha
  function showSavePasswordPrompt(data) {
    if (!data || !data.password) return;

    // Remove qualquer prompt anterior para atualizar com dados novos
    const existing = document.getElementById('__safepass_save_container');
    if (existing) existing.remove();

    const host = document.createElement('div');
    host.id = '__safepass_save_container';
    host.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 2147483647; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; pointer-events: auto;';
    
    const shadow = host.attachShadow({ mode: 'open' });
    
    shadow.innerHTML = `
      <style>
        .safepass-prompt-box {
          background: #0d1322;
          border: 1px solid rgba(109, 74, 255, 0.5);
          border-radius: 14px;
          padding: 16px 18px;
          width: 310px;
          box-shadow: 0 12px 40px rgba(0,0,0,0.85), 0 0 25px rgba(109, 74, 255, 0.35);
          color: #f8fafc;
          box-sizing: border-box;
          animation: slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes slideIn {
          from { transform: translateY(-30px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        .header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 8px;
        }
        .brand {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 14px;
          font-weight: 800;
          color: #fff;
        }
        .brand span { color: #6d4aff; }
        .close-btn {
          background: none;
          border: none;
          color: #64748b;
          font-size: 20px;
          cursor: pointer;
          line-height: 1;
          padding: 2px;
          transition: color 0.15s;
        }
        .close-btn:hover { color: #f43f5e; }
        .desc {
          font-size: 12px;
          color: #94a3b8;
          margin-bottom: 12px;
          line-height: 1.4;
        }
        .info-card {
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 8px;
          padding: 8px 12px;
          margin-bottom: 14px;
          font-size: 12px;
        }
        .info-row {
          display: flex;
          justify-content: space-between;
          margin-bottom: 4px;
        }
        .info-row:last-child { margin-bottom: 0; }
        .info-label { color: #64748b; }
        .info-val { color: #fff; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 170px; }
        .actions {
          display: flex;
          gap: 8px;
        }
        .btn {
          flex: 1;
          height: 36px;
          border-radius: 8px;
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
        }
        .btn-save {
          background: linear-gradient(135deg, #6d4aff 0%, #4f2ce0 100%);
          border: none;
          color: #fff;
          box-shadow: 0 4px 14px rgba(109, 74, 255, 0.4);
        }
        .btn-save:hover {
          filter: brightness(1.15);
          transform: translateY(-1px);
        }
        .btn-cancel {
          background: rgba(255,255,255,0.06);
          border: 1px solid rgba(255,255,255,0.12);
          color: #94a3b8;
        }
        .btn-cancel:hover {
          background: rgba(255,255,255,0.12);
          color: #fff;
        }
        .input-group {
          margin-bottom: 8px;
          text-align: left;
        }
        .input-group:last-child {
          margin-bottom: 0;
        }
        .input-label {
          display: block;
          font-size: 10px;
          font-weight: 700;
          color: #94a3b8;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          margin-bottom: 3px;
        }
        .prompt-input {
          width: 100%;
          background: rgba(0, 0, 0, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.12);
          border-radius: 6px;
          color: #fff;
          padding: 6px 8px;
          font-size: 12px;
          box-sizing: border-box;
          outline: none;
          transition: border-color 0.2s;
        }
        .prompt-input:focus {
          border-color: #6d4aff;
        }
      </style>
      <div class="safepass-prompt-box">
        <div class="header">
          <div class="brand">
            <span>🛡️</span> Safe<span>Pass</span>
          </div>
          <button class="close-btn" id="sp-close">×</button>
        </div>
        <div class="desc">Deseja salvar esta senha no seu cofre seguro?</div>
        <div class="info-card">
          <div class="input-group">
            <label class="input-label">Nome do Serviço / Site</label>
            <input type="text" id="sp-edit-title" class="prompt-input" value="${escapeHtml(data.title || data.domain)}">
          </div>
          <div class="input-group">
            <label class="input-label">Usuário / E-mail</label>
            <input type="text" id="sp-edit-user" class="prompt-input" value="${escapeHtml(data.username || '')}">
          </div>
          <div class="input-group">
            <label class="input-label">Senha</label>
            <div style="display:flex; gap:4px;">
              <input type="password" id="sp-edit-pass" class="prompt-input" value="${escapeHtml(data.password || '')}">
              <button type="button" id="sp-toggle-pass" style="background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.12); border-radius:6px; color:#fff; cursor:pointer; padding:0 8px;">👁️</button>
            </div>
          </div>
        </div>
        <div class="actions">
          <button class="btn btn-cancel" id="sp-cancel">Agora Não</button>
          <button class="btn btn-save" id="sp-save">💾 Salvar Senha</button>
        </div>
      </div>
    `;

    const mountRoot = document.documentElement || document.body;
    if (mountRoot) {
      mountRoot.appendChild(host);
    }

    const closePrompt = () => {
      if (data && data.password) dismissedSet.add(data.password);
      host.style.transition = 'opacity 0.2s, transform 0.2s';
      host.style.opacity = '0';
      host.style.transform = 'translateY(-20px)';
      setTimeout(() => host.remove(), 250);
    };

    shadow.getElementById('sp-close').onclick = closePrompt;
    shadow.getElementById('sp-cancel').onclick = closePrompt;

    shadow.getElementById('sp-toggle-pass').onclick = () => {
      const passInp = shadow.getElementById('sp-edit-pass');
      passInp.type = passInp.type === 'password' ? 'text' : 'password';
    };

    shadow.getElementById('sp-save').onclick = () => {
      if (!isExtensionValid()) return;

      const editedTitle = shadow.getElementById('sp-edit-title').value.trim() || data.domain;
      const editedUser = shadow.getElementById('sp-edit-user').value.trim();
      const editedPass = shadow.getElementById('sp-edit-pass').value;
      if (editedPass) dismissedSet.add(editedPass);

      const toSave = {
        ...data,
        title: editedTitle,
        username: editedUser,
        password: editedPass
      };

      chrome.runtime.sendMessage({ action: 'save_credential', data: toSave }, (res) => {
        if (chrome.runtime.lastError) return;
        const box = shadow.querySelector('.safepass-prompt-box');
        if (box) {
          box.innerHTML = `
            <div style="text-align: center; padding: 12px 0; color: #10b981; font-weight: 700; font-size: 13px;">
              ✅ Senha salva com sucesso!
            </div>
          `;
        }
        setTimeout(closePrompt, 1500);
      });
    };
  }
})();

// ── 5. BADGE INTERNO NOS CAMPOS DE SENHA & MENU INLINE ──────────
(function setupInFieldBadges() {
  if (window.location.hostname.includes('4u.ia.br') && window.location.pathname.includes('safepass')) {
    return;
  }

  const iconUrl = chrome.runtime.getURL('icon-16.png');
  const attachedInputs = new WeakSet();

  function scanAndAttachInputs() {
    const inputs = Array.from(document.querySelectorAll('input[type="password"]')).filter(el => {
      return el.offsetParent !== null && !el.disabled && !el.readOnly;
    });

    inputs.forEach(input => {
      if (attachedInputs.has(input)) return;
      attachedInputs.add(input);
      attachBadgeToInput(input);
    });
  }

  function attachBadgeToInput(input) {
    const wrapper = document.createElement('div');
    wrapper.className = '__safepass_badge_wrap';
    wrapper.style.cssText = `
      position: absolute;
      z-index: 2147483640;
      width: 20px;
      height: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      pointer-events: auto;
      transition: transform 0.15s, opacity 0.15s;
    `;

    wrapper.innerHTML = `
      <img src="${iconUrl}" alt="SafePass" style="width: 16px; height: 16px; border-radius: 4px; pointer-events: none; filter: drop-shadow(0 2px 4px rgba(0,0,0,0.5));">
    `;

    document.body.appendChild(wrapper);

    function updateBadgePos() {
      if (!input.offsetParent) {
        wrapper.style.display = 'none';
        return;
      }
      wrapper.style.display = 'flex';
      const rect = input.getBoundingClientRect();
      const top = rect.top + window.scrollY + (rect.height / 2) - 10;
      const left = rect.left + window.scrollX + rect.width - 26;
      wrapper.style.top = `${top}px`;
      wrapper.style.left = `${left}px`;
    }

    updateBadgePos();
    window.addEventListener('resize', updateBadgePos, { passive: true });
    window.addEventListener('scroll', updateBadgePos, { passive: true });

    // Menu inline ao clicar no ícone do SafePass dentro do input
    wrapper.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      showInlineDropdown(input, wrapper);
    });
  }

  function isDomainMatch(item, targetDomain) {
    if (!item) return false;
    const target = (targetDomain || '').replace(/^www\./i, '').toLowerCase(); // 'facebook.com'
    const targetBase = target.split('.')[0]; // 'facebook'

    // 1. Testa URL
    if (item.url) {
      try {
        const itemUrl = item.url.startsWith('http') ? item.url : 'https://' + item.url;
        const itemHost = new URL(itemUrl).hostname.replace(/^www\./i, '').toLowerCase();
        if (itemHost === target || itemHost.endsWith('.' + target) || target.endsWith('.' + itemHost)) return true;
        const itemBase = itemHost.split('.')[0];
        if (itemBase === targetBase && itemBase.length >= 3) return true;
      } catch(e) {
        if (item.url.toLowerCase().includes(target) || item.url.toLowerCase().includes(targetBase)) return true;
      }
    }

    // 2. Testa Título
    if (item.title) {
      const t = item.title.toLowerCase();
      if (t.includes(targetBase) || targetBase.includes(t) || t.includes(target)) return true;
    }

    // 3. Testa Domínio do Item
    if (item.domain) {
      const d = item.domain.toLowerCase();
      if (d.includes(targetBase) || target.includes(d)) return true;
    }

    // 4. Caso específico para grandes plataformas
    if (target.includes('facebook') && (item.title || item.url || '').toLowerCase().includes('facebook')) return true;
    if (target.includes('google') && (item.title || item.url || '').toLowerCase().includes('google')) return true;

    return false;
  }

  function showInlineDropdown(input, badge) {
    const existing = document.getElementById('__safepass_inline_dropdown');
    if (existing) {
      existing.remove();
      return;
    }

    const dropdown = document.createElement('div');
    dropdown.id = '__safepass_inline_dropdown';
    const rect = badge.getBoundingClientRect();
    const top = rect.bottom + window.scrollY + 6;
    const left = Math.max(10, rect.right + window.scrollX - 250);

    dropdown.style.cssText = `
      position: absolute;
      top: ${top}px;
      left: ${left}px;
      width: 250px;
      background: #0f172a;
      border: 1px solid rgba(109, 74, 255, 0.4);
      box-shadow: 0 10px 30px rgba(0,0,0,0.85), 0 0 15px rgba(109, 74, 255, 0.25);
      border-radius: 10px;
      padding: 8px;
      z-index: 2147483647;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 12px;
      animation: __spFadeIn 0.15s ease;
    `;

    dropdown.innerHTML = `
      <style>
        @keyframes __spFadeIn { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }
        .__sp_drop_btn {
          width: 100%;
          padding: 8px 10px;
          border-radius: 6px;
          border: none;
          background: transparent;
          color: #e2e8f0;
          font-size: 12px;
          font-weight: 500;
          text-align: left;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 8px;
          transition: background 0.15s;
          box-sizing: border-box;
        }
        .__sp_drop_btn:hover {
          background: rgba(109, 74, 255, 0.25);
          color: #fff;
        }
        .__sp_match_card {
          background: rgba(109, 74, 255, 0.18);
          border: 1px solid rgba(109, 74, 255, 0.4);
          border-radius: 8px;
          padding: 8px 10px;
          margin-bottom: 6px;
          cursor: pointer;
          transition: all 0.15s;
        }
        .__sp_match_card:hover {
          background: rgba(109, 74, 255, 0.35);
          border-color: #6d4aff;
          transform: translateY(-1px);
        }
      </style>
      <div style="padding: 4px 6px 6px; font-size: 10px; font-weight: 700; color: #94a3b8; border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between;">
        <span>🛡️ SafePass</span>
        <span style="color: #10b981;">● Ativo</span>
      </div>
      <div id="__sp_matches_box">
        <div style="font-size: 11px; color: #94a3b8; padding: 6px 0; text-align: center;">
          🔍 Buscando credenciais...
        </div>
      </div>
      <div style="border-top: 1px solid rgba(255,255,255,0.08); margin-top: 4px; padding-top: 4px;">
        <button class="__sp_drop_btn" id="__sp_gen_fill">
          <span>⚡</span> Gerar Senha Forte
        </button>
        <button class="__sp_drop_btn" id="__sp_open_ext">
          <span>🔑</span> Abrir SafePass
        </button>
      </div>
    `;

    document.body.appendChild(dropdown);

    function renderDropdownLogins(logins) {
      const matchBox = dropdown.querySelector('#__sp_matches_box');
      if (!matchBox) return;

      if (logins && logins.length > 0) {
        matchBox.innerHTML = '';
        logins.forEach(item => {
          const card = document.createElement('div');
          card.className = '__sp_match_card';
          card.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: space-between;">
              <span style="font-weight: 700; color: #fff; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 140px;">
                👤 ${escapeHtml(item.username || 'Sem usuário')}
              </span>
              <span style="font-size: 10px; background: #6d4aff; color: #fff; padding: 3px 8px; border-radius: 4px; font-weight: 700; display: inline-flex; align-items: center; gap: 2px;">
                ⚡ Preencher
              </span>
            </div>
            <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">
              ${escapeHtml(item.title || item.domain || 'Facebook')}
            </div>
          `;

          card.onclick = (ev) => {
            ev.stopPropagation();
            performAutoFill(item.username, item.password);
            dropdown.remove();
          };

          matchBox.appendChild(card);
        });
      } else {
        matchBox.innerHTML = `
          <div style="font-size: 11px; color: #94a3b8; padding: 4px 6px 6px; text-align: center;">
            Nenhuma senha salva para este site.
          </div>
        `;
      }
    }

    // Consulta senhas correspondentes ao domínio atual
    const domain = window.location.hostname.replace(/^www\./i, '').toLowerCase();
    if (isExtensionValid()) {
      // 1. Busca direto no storage local (zero latency)
      chrome.storage.local.get(['safepass_unlocked_vault_cache', 'safepass_pending_vault_items'], (res) => {
        if (chrome.runtime.lastError || !isExtensionValid()) return;
        const cache = res['safepass_unlocked_vault_cache'] || [];
        const pending = res['safepass_pending_vault_items'] || [];
        const combined = [...cache, ...pending];
        const localMatches = [];
        const added = new Set();

        combined.forEach(item => {
          if (isDomainMatch(item, domain)) {
            const key = (item.username || '') + '|' + (item.password || '');
            if (!added.has(key)) {
              added.add(key);
              localMatches.push(item);
            }
          }
        });

        if (localMatches.length > 0) {
          renderDropdownLogins(localMatches);
        } else {
          // 2. Consulta background caso haja auto-descriptografia
          chrome.runtime.sendMessage({ action: 'get_matched_logins', domain }, (bRes) => {
            if (chrome.runtime.lastError || !isExtensionValid()) return;
            const logins = (bRes && bRes.logins) ? bRes.logins : [];
            renderDropdownLogins(logins);
          });
        }
      });
    }

    // Fechar ao clicar fora
    const onDocClick = (ev) => {
      if (!dropdown.contains(ev.target) && ev.target !== badge) {
        dropdown.remove();
        document.removeEventListener('click', onDocClick);
      }
    };
    setTimeout(() => document.addEventListener('click', onDocClick), 50);

    // Gerar senha forte na hora
    dropdown.querySelector('#__sp_gen_fill').onclick = () => {
      const strongPass = generateQuickPassword(20);
      setNativeValue(input, strongPass);
      dropdown.remove();
    };

    dropdown.querySelector('#__sp_open_ext').onclick = () => {
      window.open('https://4u.ia.br/app/safepass/', '_blank');
      dropdown.remove();
    };
  }

  function generateQuickPassword(len = 20) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}';
    const array = new Uint32Array(len);
    crypto.getRandomValues(array);
    let pass = '';
    for (let i = 0; i < len; i++) {
      pass += chars[array[i] % chars.length];
    }
    return pass;
  }

  // Monitora a página para novos inputs dinâmicos
  const scanInterval = setInterval(() => {
    if (!isExtensionValid()) {
      clearInterval(scanInterval);
      return;
    }
    scanAndAttachInputs();
  }, 2000);
  scanAndAttachInputs();
  const observer = new MutationObserver(() => {
    if (isExtensionValid()) scanAndAttachInputs();
  });
  observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
})();
