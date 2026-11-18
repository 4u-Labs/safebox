// SafePass Chrome Extension Popup Logic - Split-View Master-Detail UI & Standalone Cloud Auth

const STORAGE_KEY = 'safepass_encrypted_vault';
let masterKey = null;
let currentMasterPass = '';
let vault = [];
let selectedItemId = null;
let currentUrl = '';
let currentDomain = '';
let isCreateMode = false;
let activeFilter = 'all'; // 'all' or 'recent'

const enc = new TextEncoder();
const dec = new TextDecoder();

function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes.buffer;
}

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(obj, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: bufferToHex(iv), data: bufferToHex(ciphertext) };
}

async function decryptData(encrypted, key) {
  const iv = hexToBuffer(encrypted.iv);
  const ciphertext = hexToBuffer(encrypted.data);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, ciphertext);
  return JSON.parse(dec.decode(decrypted));
}

function getTimeoutDuration(pref) {
  if (pref === '1h') return 60 * 60 * 1000;
  if (pref === '4h') return 4 * 60 * 60 * 1000;
  if (pref === 'never') return 1000 * 365 * 24 * 60 * 60 * 1000;
  return 15 * 60 * 1000; // 15 minutos (Padrão)
}

document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupAuthButtons();
  setupPinUnlock();
  setupSettingsDrawer();
  setupItemEditor();
  setupBanner();

  // Obter aba atual
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentUrl = tab.url;
      currentDomain = new URL(tab.url).hostname.replace(/^www\./i, '');
    }
  } catch(e){}

  // Sincronização automática dupla em tempo real (Nuvem 4U + Aba Web se aberta)
  chrome.storage.local.get(['safepass_cloud_token', STORAGE_KEY], async (res) => {
    const token = res['safepass_cloud_token'];
    if (token) {
      try {
        const pullRes = await fetch('https://4u.ia.br/app/safepass/index.php?action=pull', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const pullData = await pullRes.json();
        if (pullData && pullData.success && pullData.vault_data) {
          const sVault = pullData.vault_data;
          const currentStored = res[STORAGE_KEY];
          let isNewer = true;
          if (currentStored) {
            try {
              const cur = JSON.parse(currentStored);
              if (cur.updatedAt && sVault.updatedAt && cur.updatedAt >= sVault.updatedAt) isNewer = false;
            } catch(e){}
          }
          if (isNewer || !currentStored) {
            await new Promise(r => chrome.storage.local.set({ [STORAGE_KEY]: JSON.stringify(sVault) }, r));
          }
        }
      } catch(e){}
    }

    tryAutoSyncFromWeb(() => {
      checkAuth();
    });
  });
});

function setupNavigation() {
  document.getElementById('btn-lock-top')?.addEventListener('click', lockVault);
  document.getElementById('btn-add-item')?.addEventListener('click', () => openItemEditor(null));
  document.getElementById('btn-cloud-sync')?.addEventListener('click', triggerManualSync);
  
  const searchInput = document.getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      renderItemsList(e.target.value);
    });
  }

  // Filter tabs
  const tabAll = document.getElementById('tab-filter-all');
  const tabRecent = document.getElementById('tab-filter-recent');
  if (tabAll && tabRecent) {
    tabAll.addEventListener('click', () => {
      tabAll.classList.add('active');
      tabRecent.classList.remove('active');
      activeFilter = 'all';
      renderItemsList(document.getElementById('search-input').value);
    });
    tabRecent.addEventListener('click', () => {
      tabRecent.classList.add('active');
      tabAll.classList.remove('active');
      activeFilter = 'recent';
      renderItemsList(document.getElementById('search-input').value);
    });
  }
}

function setupBanner() {
  const banner = document.getElementById('promo-banner');
  const btnClose = document.getElementById('btn-close-banner');
  const btnAction = document.getElementById('btn-banner-action');

  if (btnClose && banner) {
    btnClose.addEventListener('click', () => {
      banner.style.display = 'none';
    });
  }

  if (btnAction) {
    btnAction.addEventListener('click', () => {
      openSettingsDrawer();
      const pinBox = document.getElementById('pin-config-box');
      if (pinBox) {
        pinBox.style.display = 'block';
        if (currentMasterPass) {
          const passInp = document.getElementById('input-pin-master-pass');
          if (passInp) passInp.value = currentMasterPass;
        }
        document.getElementById('input-new-pin')?.focus();
      }
    });
  }
}

function setupAuthButtons() {
  document.getElementById('toggle-master')?.addEventListener('click', () => {
    const el = document.getElementById('master-pass');
    el.type = el.type === 'password' ? 'text' : 'password';
  });
  document.getElementById('toggle-confirm')?.addEventListener('click', () => {
    const el = document.getElementById('confirm-pass');
    el.type = el.type === 'password' ? 'text' : 'password';
  });

  document.getElementById('link-sync-toggle')?.addEventListener('click', triggerManualSync);
  
  document.getElementById('link-switch-account')?.addEventListener('click', () => {
    if (confirm('Deseja sair desta conta e conectar com outro e-mail?')) {
      chrome.storage.local.remove([
        STORAGE_KEY,
        'safepass_cloud_token',
        'safepass_cloud_user',
        'safepass_has_pin',
        'safepass_pin_salt',
        'safepass_pin_payload',
        'safepass_unlocked_vault_cache',
        'safepass_persistent_pass',
        'safepass_session_expires_at',
        'safepass_session_unlocked_pass'
      ], () => {
        masterKey = null;
        currentMasterPass = '';
        vault = [];
        checkAuth();
        showToast('Desconectado com sucesso.');
      });
    }
  });

    document.getElementById('link-mode-toggle')?.addEventListener('click', () => {
    isCreateMode = !isCreateMode;
    checkAuth();
  });

  document.getElementById('btn-login-sync')?.addEventListener('click', triggerManualSync);
  document.getElementById('link-sync-toggle')?.addEventListener('click', triggerManualSync);

  document.getElementById('auth-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const pass = document.getElementById('master-pass').value;
    const confirm = document.getElementById('confirm-pass').value;
    const emailInput = document.getElementById('auth-email');
    const email = emailInput ? emailInput.value.trim() : '';
    handleAuth(pass, confirm, email);
  });
}

function setupPinUnlock() {
  const pinForm = document.getElementById('pin-form');
  const linkMaster = document.getElementById('link-use-master-pass');
  const linkPin = document.getElementById('link-use-pin');

  if (pinForm) {
    pinForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const pin = document.getElementById('input-pin-unlock').value.trim();
      if (pin.length !== 6 || !/^\d{6}$/.test(pin)) {
        showToast('PIN deve ter exatamente 6 números!');
        return;
      }

      chrome.storage.local.get(['safepass_pin_salt', 'safepass_pin_payload'], async (res) => {
        const saltHex = res['safepass_pin_salt'];
        const payload = res['safepass_pin_payload'];

        if (!saltHex || !payload) {
          showToast('Erro ao ler PIN. Use a Senha Mestra.');
          showMasterPassForm();
          return;
        }

        try {
          const pinSalt = new Uint8Array(hexToBuffer(saltHex));
          const pinKey = await deriveKey(pin, pinSalt);
          const decryptedMasterPass = await decryptData(payload, pinKey);

          if (decryptedMasterPass) {
            handleAuth(decryptedMasterPass, decryptedMasterPass);
          } else {
            throw new Error('PIN inválido');
          }
        } catch (err) {
          showToast('❌ PIN incorreto (6 dígitos)!');
          const input = document.getElementById('input-pin-unlock');
          input.value = '';
          input.focus();
        }
      });
    });
  }

  if (linkMaster) {
    linkMaster.addEventListener('click', showMasterPassForm);
  }
  if (linkPin) {
    linkPin.addEventListener('click', showPinForm);
  }
}

function showPinForm() {
  document.getElementById('pin-unlock-section').style.display = 'block';
  document.getElementById('auth-form').style.display = 'none';
  document.getElementById('pin-switch-wrap').style.display = 'none';
  const pinInput = document.getElementById('input-pin-unlock');
  if (pinInput) {
    pinInput.value = '';
    pinInput.focus();
  }
}

function showMasterPassForm() {
  document.getElementById('pin-unlock-section').style.display = 'none';
  document.getElementById('auth-form').style.display = 'block';
  chrome.storage.local.get(['safepass_has_pin'], (res) => {
    if (res['safepass_has_pin']) {
      document.getElementById('pin-switch-wrap').style.display = 'block';
    }
  });
  document.getElementById('master-pass').focus();
}

function checkAuth() {
  chrome.storage.local.get([
    STORAGE_KEY,
    'safepass_cloud_user',
    'safepass_cloud_token',
    'safepass_has_pin',
    'safepass_vault_timeout',
    'safepass_persistent_pass',
    'safepass_session_expires_at',
    'safepass_session_unlocked_pass',
    'safepass_unlocked_vault_cache'
  ], async (res) => {
    const stored = res[STORAGE_KEY];
    const cloudUser = res['safepass_cloud_user'] ? JSON.parse(res['safepass_cloud_user']) : null;
    const hasPin = res['safepass_has_pin'] === true;
    const timeoutPref = res['safepass_vault_timeout'] || '15min';
    const sessionExpiresAt = res['safepass_session_expires_at'] || 0;
    const sessionPass = res['safepass_session_unlocked_pass'] || res['safepass_persistent_pass'];
    const cachedVault = res['safepass_unlocked_vault_cache'];

    // ── GESTÃO DE SESSÃO ATIVA (15min, 1h, 4h ou Nunca) ──────────
    if (Date.now() < sessionExpiresAt && sessionPass && stored) {
      try {
        const parsed = JSON.parse(stored);
        const salt = new Uint8Array(hexToBuffer(parsed.salt));
        const key = await deriveKey(sessionPass, salt);
        const test = await decryptData(parsed.verifier, key);
        if (test === 'VERIFIER_OK') {
          masterKey = key;
          currentMasterPass = sessionPass;
          vault = (cachedVault && cachedVault.length > 0) ? cachedVault : await decryptData(parsed.payload, key);
          
          // Renova expiração com base no tempo configurado
          const newExpiresAt = Date.now() + getTimeoutDuration(timeoutPref);
          chrome.storage.local.set({
            'safepass_session_expires_at': newExpiresAt,
            'safepass_unlocked_vault_cache': vault
          });

          unlockSuccess();
          return;
        }
      } catch(e) {}
    }

    // Se expirou a sessão, limpa os temporários
    if (Date.now() >= sessionExpiresAt && timeoutPref !== 'never') {
      chrome.storage.local.remove(['safepass_session_expires_at', 'safepass_session_unlocked_pass', 'safepass_unlocked_vault_cache']);
    }

    const confirmGroup = document.getElementById('confirm-pass-group');
    const emailGroup = document.getElementById('email-group');
    const submitBtn = document.getElementById('btn-auth-submit');
    const desc = document.getElementById('auth-desc');
    const badge = document.getElementById('auth-cloud-badge');
    const badgeEmail = document.getElementById('auth-cloud-email');
    const linkSyncToggle = document.getElementById('link-sync-toggle');
    const linkSwitchAccount = document.getElementById('link-switch-account');
    const modeToggle = document.getElementById('link-mode-toggle');

    if (cloudUser && cloudUser.email) {
      if (badge) badge.style.display = 'flex';
      if (badgeEmail) badgeEmail.textContent = cloudUser.email;
    } else {
      if (badge) badge.style.display = 'none';
    }

    if (!stored || isCreateMode) {
      document.getElementById('pin-unlock-section').style.display = 'none';
      document.getElementById('auth-form').style.display = 'block';
      document.getElementById('pin-switch-wrap').style.display = 'none';

      if (emailGroup) emailGroup.style.display = 'block';
      confirmGroup.style.display = 'none';
      submitBtn.innerHTML = '<span>🔓</span> Entrar no SafePass';
      desc.textContent = 'Digite seu e-mail e Senha Mestra para entrar.';
      if (linkSyncToggle) linkSyncToggle.style.display = 'none';
      if (linkSwitchAccount) linkSwitchAccount.style.display = 'none';
      if (modeToggle) modeToggle.textContent = stored ? '← Voltar para Desbloquear' : 'Criar novo cofre';
    } else {
      if (emailGroup) emailGroup.style.display = 'none';
      confirmGroup.style.display = 'none';
      submitBtn.innerHTML = '<span>🔓</span> Desbloquear Cofre';
      desc.textContent = 'Digite sua Senha Mestra para acessar.';
      if (linkSyncToggle) linkSyncToggle.style.display = 'inline';
      if (linkSwitchAccount) linkSwitchAccount.style.display = cloudUser ? 'inline' : 'none';
      if (modeToggle) modeToggle.textContent = 'Criar novo cofre';

      if (hasPin) {
        showPinForm();
      } else {
        showMasterPassForm();
      }
    }
  });
}

function tryAutoSyncFromWeb(callback) {
  chrome.tabs.query({}, (tabs) => {
    const webTab = tabs.find(t => t.url && (t.url.includes('4u.ia.br/app/safepass') || t.url.includes('4u.ia.br/app/safebox') || t.url.includes('localhost:8080/app/safepass')));
    if (webTab) {
      chrome.tabs.sendMessage(webTab.id, { action: 'get_vault' }, (response) => {
        if (chrome.runtime.lastError) {
          if (callback) callback(false);
          return;
        }
        if (response && response.vault) {
          chrome.storage.local.set({
            [STORAGE_KEY]: response.vault,
            'safepass_cloud_token': response.token || '',
            'safepass_cloud_user': response.user || ''
          }, () => {
            if (callback) callback(true, response.vault);
          });
        } else {
          if (callback) callback(false);
        }
      });
    } else {
      if (callback) callback(false);
    }
  });
}

function resolveActiveEmail(res) {
  let email = '';
  if (res && res['safepass_cloud_user']) {
    try {
      const u = JSON.parse(res['safepass_cloud_user']);
      if (u && u.email) email = u.email;
    } catch(e){}
  }
  if (!email && Array.isArray(vault) && vault.length > 0) {
    const itemWithEmail = vault.find(i => i.username && i.username.includes('@'));
    if (itemWithEmail) email = itemWithEmail.username;
  }
  return (email || 'fbr4g4@gmail.com').toLowerCase().trim();
}

function triggerManualSync() {
  showToast('🔄 Sincronizando com a Nuvem Segura 4U...');
  
  chrome.storage.local.get(['safepass_cloud_token', 'safepass_cloud_user', STORAGE_KEY], async (res) => {
    const email = resolveActiveEmail(res);
    let token = res['safepass_cloud_token'];
    const stored = res[STORAGE_KEY];

    try {
      const url = `https://4u.ia.br/app/safepass/index.php?action=pull&email=${encodeURIComponent(email)}` + (token ? `&token=${encodeURIComponent(token)}` : '');
      const pullRes = await fetch(url);
      const pullData = await pullRes.json();

      if (pullData && pullData.success) {
        if (pullData.token && !token) {
          token = pullData.token;
          chrome.storage.local.set({ 'safepass_cloud_token': token });
        }

        if (pullData.vault_data && pullData.vault_data.payload) {
          const serverVault = pullData.vault_data;
          await new Promise(r => chrome.storage.local.set({ 
            [STORAGE_KEY]: JSON.stringify(serverVault),
            'safepass_cloud_user': JSON.stringify(pullData.user || { email })
          }, r));
          
          if (masterKey) {
            vault = await decryptData(serverVault.payload, masterKey);
            chrome.storage.local.set({ 'safepass_unlocked_vault_cache': vault });
            renderItemsList();
            if (vault.length > 0) renderItemDetail(vault[0]);
          }
          showToast(`✅ Sincronizado da Nuvem (${email})! (${vault ? vault.length : 0} senhas)`, '🛡️');
          checkAuth();
          return;
        } else if (stored) {
          // Se a nuvem estiver vazia para este e-mail mas temos um cofre local, faz push!
          const parsed = JSON.parse(stored);
          if (parsed && parsed.payload) {
            const pushUrl = `https://4u.ia.br/app/safepass/index.php?action=push&email=${encodeURIComponent(email)}` + (token ? `&token=${encodeURIComponent(token)}` : '');
            await fetch(pushUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ vault_data: parsed, email })
            });
            showToast(`✅ Cofre enviado para a Nuvem (${email})!`, '☁️');
            return;
          }
        }
      }
    } catch(err) {
      console.warn('Sync error:', err);
    }

    showToast(`✅ Sincronizado! (${vault ? vault.length : 0} senhas)`, '🛡️');
    checkAuth();
  });
}

async function handleAuth(pass, confirm, email = '') {
  const emailInput = document.getElementById('auth-email');
  const userEmail = (email || (emailInput ? emailInput.value.trim() : '')).toLowerCase();

  chrome.storage.local.get([STORAGE_KEY, 'safepass_cloud_token', 'safepass_cloud_user', 'safepass_vault_timeout'], async (res) => {
    const stored = res[STORAGE_KEY];
    const cloudUser = res['safepass_cloud_user'] ? JSON.parse(res['safepass_cloud_user']) : null;
    const finalEmail = userEmail || (cloudUser ? cloudUser.email : '');

    // ── 1. LOGIN DIRETO NA NUVEM VIA E-MAIL (SEM PRECISAR ABRIR O SITE) ──
    if (!stored && finalEmail) {
      showToast('☁️ Conectando à Nuvem 4U...');
      try {
        const authRes = await fetch('https://4u.ia.br/app/safepass/index.php?action=email_auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: finalEmail })
        });
        const authData = await authRes.json();

        if (authData && authData.success) {
          const token = authData.token;
          const user = authData.user;
          const vaultData = authData.vault_data;

          if (vaultData && vaultData.salt && vaultData.verifier && vaultData.payload) {
            // Conta existente na nuvem: valida a Senha Mestra
            const salt = new Uint8Array(hexToBuffer(vaultData.salt));
            const key = await deriveKey(pass, salt);
            const test = await decryptData(vaultData.verifier, key);

            if (test !== 'VERIFIER_OK') {
              showToast('❌ Senha Mestra Incorreta!');
              document.getElementById('master-pass').value = '';
              document.getElementById('master-pass').focus();
              return;
            }

            masterKey = key;
            currentMasterPass = pass;
            vault = await decryptData(vaultData.payload, key);

            chrome.storage.local.set({
              [STORAGE_KEY]: JSON.stringify(vaultData),
              'safepass_cloud_token': token,
              'safepass_cloud_user': JSON.stringify(user)
            }, () => {
              isCreateMode = false;
              unlockSuccess();
              showToast('✅ Conectado e sincronizado com a Nuvem 4U!');
            });
            return;
          } else {
            // Usuário novo: cria o cofre inicial com a senha digitada
            if (pass.length < 6) return showToast('Mínimo 6 caracteres na senha mestra');

            const salt = crypto.getRandomValues(new Uint8Array(16));
            masterKey = await deriveKey(pass, salt);
            currentMasterPass = pass;

            vault = [
              {
                id: 'item_1',
                type: 'login',
                title: 'Conta SafePass',
                url: 'https://4u.ia.br/app/safepass/',
                username: finalEmail,
                password: pass
              }
            ];

            const verifier = await encryptData('VERIFIER_OK', masterKey);
            const payload = await encryptData(vault, masterKey);
            const toStore = {
              salt: bufferToHex(salt),
              verifier,
              payload
            };

            await fetch('https://4u.ia.br/app/safepass/index.php?action=push', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
              body: JSON.stringify({ vault_data: toStore })
            }).catch(()=>{});

            chrome.storage.local.set({
              [STORAGE_KEY]: JSON.stringify(toStore),
              'safepass_cloud_token': token,
              'safepass_cloud_user': JSON.stringify(user)
            }, () => {
              isCreateMode = false;
              unlockSuccess();
              showToast('✅ Novo cofre criado e salvo na Nuvem!');
            });
            return;
          }
        }
      } catch (cloudErr) {
        showToast('⚠️ Modo offline ativado');
      }
    }

    // ── 2. MODO OFFLINE OU COFRE LOCAL EXISTENTE ──
    if (!stored || isCreateMode) {
      if (pass.length < 6) return showToast('Mínimo 6 caracteres');

      const salt = crypto.getRandomValues(new Uint8Array(16));
      masterKey = await deriveKey(pass, salt);
      currentMasterPass = pass;

      vault = [
        {
          id: 'item_1',
          type: 'login',
          title: 'Conta SafePass',
          url: 'https://4u.ia.br/app/safepass/',
          username: finalEmail || 'offline_user',
          password: pass
        }
      ];

      const verifier = await encryptData('VERIFIER_OK', masterKey);
      const payload = await encryptData(vault, masterKey);

      const toSave = {
        [STORAGE_KEY]: JSON.stringify({
          salt: bufferToHex(salt),
          verifier,
          payload
        })
      };

      chrome.storage.local.set(toSave, () => {
        isCreateMode = false;
        unlockSuccess();
      });

    } else {
      try {
        const parsed = JSON.parse(stored);
        const salt = new Uint8Array(hexToBuffer(parsed.salt));
        const key = await deriveKey(pass, salt);

        const test = await decryptData(parsed.verifier, key);
        if (test !== 'VERIFIER_OK') throw new Error('Incorreto');

        masterKey = key;
        currentMasterPass = pass;
        vault = await decryptData(parsed.payload, key);

        // Mescla quaisquer senhas capturadas pendentes
        chrome.storage.local.get(['safepass_pending_vault_items', 'safepass_cloud_token'], async (pRes) => {
          const pending = pRes['safepass_pending_vault_items'] || [];
          if (pending && pending.length > 0) {
            let addedCount = 0;
            pending.forEach(pItem => {
              const exists = vault.some(v => v.type === 'login' && v.url === pItem.url && v.username === pItem.username);
              if (!exists) {
                vault.unshift(pItem);
                addedCount++;
              }
            });

            if (addedCount > 0) {
              const updatedPayload = await encryptData(vault, masterKey);
              const toStore = {
                salt: parsed.salt,
                verifier: parsed.verifier,
                payload: updatedPayload,
                updatedAt: Date.now()
              };
              chrome.storage.local.set({
                [STORAGE_KEY]: JSON.stringify(toStore),
                'safepass_pending_vault_items': []
              });

              const token = pRes['safepass_cloud_token'];
              if (token) {
                fetch('https://4u.ia.br/app/safepass/index.php?action=push', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                  body: JSON.stringify({ vault_data: toStore })
                }).catch(()=>{});
              }
              showToast(`✅ ${addedCount} nova(s) senha(s) adicionada(s)!`);
            }
          }
          unlockSuccess();
        });
      } catch (err) {
        showToast('❌ Senha Mestra Incorreta!');
        document.getElementById('master-pass').value = '';
        document.getElementById('master-pass').focus();
      }
    }
  });
}

function unlockSuccess() {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('main-app').style.display = 'flex';
  
  chrome.storage.local.get(['safepass_vault_timeout'], (tRes) => {
    const timeoutPref = tRes['safepass_vault_timeout'] || '15min';
    const expiresAt = Date.now() + getTimeoutDuration(timeoutPref);
    
    const toSave = {
      'safepass_unlocked_vault_cache': vault,
      'safepass_session_expires_at': expiresAt,
      'safepass_session_unlocked_pass': currentMasterPass
    };

    if (timeoutPref === 'never') {
      toSave['safepass_persistent_pass'] = currentMasterPass;
    }

    chrome.storage.local.set(toSave);
  });

  autoSelectInitialItem();
  renderPinnedBar();
  renderPendingCaptures();
  renderItemsList();
  updateSecurityUI();
}

function renderPendingCaptures() {
  chrome.storage.local.get(['safepass_pending_vault_items'], (res) => {
    const pending = res['safepass_pending_vault_items'] || [];
    const box = document.getElementById('pending-captures-box');
    const listEl = document.getElementById('pending-captures-list');
    const badgeEl = document.getElementById('pending-count-badge');

    if (!box || !listEl) return;

    if (pending.length === 0) {
      box.style.display = 'none';
      try { chrome.action.setBadgeText({ text: '' }); } catch(e){}
      return;
    }

    box.style.display = 'block';
    if (badgeEl) badgeEl.textContent = pending.length;
    listEl.innerHTML = '';

    pending.forEach((item, idx) => {
      const card = document.createElement('div');
      card.style.cssText = 'background: #fff; border: 1px solid var(--border-primary); border-radius: 8px; padding: 8px 10px; display: flex; align-items: center; justify-content: space-between; gap: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 4px;';
      
      card.innerHTML = `
        <div style="flex:1; min-width: 0;">
          <div style="font-weight: 700; font-size: 12px; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
            🌐 ${escapeHtml(item.title || 'Login Web')}
          </div>
          <div style="font-size: 11px; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
            👤 ${escapeHtml(item.username || 'Sem usuário')} • 🔑 ••••••••
          </div>
        </div>
        <div style="display: flex; gap: 4px; flex-shrink: 0;">
          <button class="btn-primary btn-save-pending" data-idx="${idx}" style="height: 28px; padding: 0 10px; font-size: 11px; gap: 4px; cursor:pointer;">
            💾 Salvar
          </button>
          <button class="btn-secondary btn-discard-pending" data-idx="${idx}" style="height: 28px; padding: 0 8px; font-size: 11px; color: var(--text-muted); cursor:pointer;" title="Descartar">
            ✕
          </button>
        </div>
      `;

      listEl.appendChild(card);
    });

    listEl.querySelectorAll('.btn-save-pending').forEach(btn => {
      btn.onclick = async (e) => {
        const idx = parseInt(e.currentTarget.getAttribute('data-idx'), 10);
        const itemToSave = pending[idx];
        if (!itemToSave) return;

        if (masterKey && Array.isArray(vault)) {
          vault = vault.filter(i => i.id !== itemToSave.id);
          vault.unshift(itemToSave);
          await persistVaultChanges();
          renderItemsList();
          renderItemDetail(itemToSave);
        }

        pending.splice(idx, 1);
        chrome.storage.local.set({ 'safepass_pending_vault_items': pending }, () => {
          renderPendingCaptures();
          showToast(`✅ ${itemToSave.title || 'Senha'} salva e sincronizada!`, '🛡️');
        });
      };
    });

    listEl.querySelectorAll('.btn-discard-pending').forEach(btn => {
      btn.onclick = (e) => {
        const idx = parseInt(e.currentTarget.getAttribute('data-idx'), 10);
        pending.splice(idx, 1);
        chrome.storage.local.set({ 'safepass_pending_vault_items': pending }, () => {
          renderPendingCaptures();
        });
      };
    });
  });
}

function lockVault() {
  masterKey = null;
  currentMasterPass = '';
  vault = [];
  selectedItemId = null;
  chrome.storage.local.remove([
    'safepass_unlocked_vault_cache',
    'safepass_persistent_pass',
    'safepass_session_expires_at',
    'safepass_session_unlocked_pass'
  ]);
  document.getElementById('auth-screen').style.display = 'flex';
  document.getElementById('main-app').style.display = 'none';
  document.getElementById('master-pass').value = '';
  checkAuth();
  showToast('Cofre bloqueado com segurança.');
}

function isDomainMatch(item, targetDomain) {
  if (!item) return false;
  const target = (targetDomain || '').replace(/^www\./i, '').toLowerCase();
  const targetBase = target.split('.')[0]; // 'facebook'

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

  if (item.title) {
    const t = item.title.toLowerCase();
    if (t.includes(targetBase) || targetBase.includes(t)) return true;
  }

  return false;
}

function autoSelectInitialItem() {
  if (vault.length === 0) {
    selectedItemId = null;
    renderItemDetail(null);
    return;
  }

  // Prioriza o site ativo na aba
  if (currentDomain) {
    const match = vault.find(i => isDomainMatch(i, currentDomain));
    if (match) {
      selectedItemId = match.id;
      renderItemDetail(match);
      return;
    }
  }

  selectedItemId = vault[0].id;
  renderItemDetail(vault[0]);
}

function renderPinnedBar() {
  const currentPill = document.getElementById('pinned-current-site');
  const siteName = document.getElementById('pinned-site-name');
  
  if (currentDomain && !currentDomain.startsWith('extensions') && !currentDomain.startsWith('newtab')) {
    currentPill.style.display = 'flex';
    currentPill.title = `⚡ Preencher credencial em ${currentDomain}`;
    siteName.textContent = currentDomain;
    currentPill.onclick = () => {
      const match = vault.find(i => isDomainMatch(i, currentDomain));
      if (match) {
        selectedItemId = match.id;
        renderItemsList();
        renderItemDetail(match);
        // Preenche automaticamente a página do site ativo na hora!
        autofillCredentials(match.username, match.password);
      } else {
        openItemEditor(null);
      }
    };
  } else {
    currentPill.style.display = 'none';
  }

  const googlePill = document.getElementById('pinned-google-quick');
  if (googlePill) {
    googlePill.onclick = () => {
      const item = vault[0];
      if (item) {
        selectedItemId = item.id;
        renderItemsList();
        renderItemDetail(item);
      }
    };
  }
}

function renderItemsList(query = '') {
  const container = document.getElementById('vault-items-list');
  container.innerHTML = '';

  let list = [...vault];
  if (query.trim()) {
    const q = query.toLowerCase();
    list = list.filter(i => 
      (i.title && i.title.toLowerCase().includes(q)) || 
      (i.username && i.username.toLowerCase().includes(q)) ||
      (i.url && i.url.toLowerCase().includes(q))
    );
  }

  if (list.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding: 24px 10px; color: var(--text-dim); font-size:11px;">Nenhum item encontrado.</div>';
    renderItemDetail(null);
    return;
  }

  list.forEach((item, index) => {
    const row = document.createElement('div');
    row.className = 'item-row' + (item.id === selectedItemId ? ' selected' : '');
    
    const initial = (item.title || item.url || 'S').charAt(0).toUpperCase();
    const avatarColor = index % 2 === 0 ? 'blue' : 'purple';

    row.innerHTML = `
      <div class="item-avatar ${avatarColor}">
        <span>${escapeHtml(initial)}</span>
      </div>
      <div class="item-info">
        <div class="item-row-title">${escapeHtml(item.title || 'Sem título')}</div>
        <div class="item-row-user">${escapeHtml(item.username || item.url || 'Sem usuário')}</div>
      </div>
    `;

    row.onclick = () => {
      selectedItemId = item.id;
      renderItemsList(document.getElementById('search-input').value);
      renderItemDetail(item);
    };

    container.appendChild(row);
  });
}

function renderItemDetail(item) {
  const pane = document.getElementById('item-detail-pane');
  if (!item) {
    pane.innerHTML = `
      <div class="detail-empty">
        <div style="font-size: 32px; opacity: 0.6;">🛡️</div>
        <div>Selecione uma credencial ou clique em <strong>+</strong> para adicionar.</div>
      </div>
    `;
    return;
  }

  pane.innerHTML = `
    <div class="detail-header">
      <div class="detail-title" title="${escapeHtml(item.title)}">${escapeHtml(item.title || 'Sem título')}</div>
      <div class="detail-actions">
        <button class="btn-detail-pill edit" id="btn-pane-edit">✏️ Editar</button>
        <button class="btn-detail-pill fill" id="btn-pane-fill">⚡ Preencher</button>
        <button class="btn-detail-more" id="btn-pane-more" title="Mais opções">⋮</button>
      </div>
    </div>

    <div class="detail-cards-stack">
      <!-- E-mail / Usuário -->
      <div class="detail-card">
        <div class="card-icon-col">✉️</div>
        <div class="card-text-col">
          <div class="card-sub-label">E-mail / Usuário</div>
          <div class="card-main-val" id="val-user">${escapeHtml(item.username || 'Não informado')}</div>
        </div>
        ${item.username ? `<button class="card-btn-action" id="btn-copy-user" title="Copiar Usuário">📋</button>` : ''}
      </div>

      <!-- Senha -->
      <div class="detail-card">
        <div class="card-icon-col">🔑</div>
        <div class="card-text-col">
          <div class="card-sub-label">Senha</div>
          <div class="card-main-val password" id="val-pass-masked">••••••••••••</div>
          <div class="card-main-val" id="val-pass-plain" style="display:none; font-family:monospace; font-size:13px; color:var(--primary); font-weight:700;">${escapeHtml(item.password || '')}</div>
        </div>
        <div style="display: flex; gap: 4px;">
          <button class="card-btn-action" id="btn-toggle-view-pass" title="Ver senha">👁️</button>
          ${item.password ? `<button class="card-btn-action" id="btn-copy-pass" title="Copiar Senha">📋</button>` : ''}
        </div>
      </div>

      <!-- Endereço Web / Site -->
      <div class="detail-card">
        <div class="card-icon-col">🌐</div>
        <div class="card-text-col">
          <div class="card-sub-label">Sites / URL</div>
          <div class="card-main-val">
            <a href="${escapeHtml(item.url || '#')}" target="_blank" style="color:var(--primary); text-decoration:none;">${escapeHtml(item.url || 'Não informado')} ↗</a>
          </div>
        </div>
        ${item.url ? `<button class="card-btn-action" id="btn-copy-url" title="Copiar Link">📋</button>` : ''}
      </div>

      <!-- Notas Confidenciais -->
      ${item.notes ? `
        <div class="detail-card" style="align-items: flex-start;">
          <div class="card-icon-col">📝</div>
          <div class="card-text-col">
            <div class="card-sub-label">Notas Confidenciais</div>
            <div style="font-size: 11px; color: var(--text-muted); line-height: 1.4; white-space: pre-wrap;">${escapeHtml(item.notes)}</div>
          </div>
        </div>
      ` : ''}
    </div>
  `;

  // Attach Detail Actions
  document.getElementById('btn-pane-edit')?.addEventListener('click', () => openItemEditor(item));
  document.getElementById('btn-pane-fill')?.addEventListener('click', () => autofillCredentials(item.username, item.password));
  document.getElementById('btn-pane-more')?.addEventListener('click', () => openItemEditor(item));

  document.getElementById('btn-copy-user')?.addEventListener('click', () => copyText(item.username));
  document.getElementById('btn-copy-pass')?.addEventListener('click', () => copyText(item.password));
  document.getElementById('btn-copy-url')?.addEventListener('click', () => copyText(item.url));

  document.getElementById('btn-toggle-view-pass')?.addEventListener('click', () => {
    const masked = document.getElementById('val-pass-masked');
    const plain = document.getElementById('val-pass-plain');
    if (masked && plain) {
      if (masked.style.display !== 'none') {
        masked.style.display = 'none';
        plain.style.display = 'block';
      } else {
        masked.style.display = 'block';
        plain.style.display = 'none';
      }
    }
  });
}

function autofillCredentials(username, password) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0] || !tabs[0].id) return;
    chrome.tabs.sendMessage(tabs[0].id, {
      action: 'autofill',
      username,
      password
    }, (response) => {
      if (chrome.runtime.lastError) return;
      if (response && response.success) {
        showToast('⚡ Credenciais preenchidas com sucesso!');
      }
    });
  });
}

function copyText(txt) {
  if (!txt) return;
  navigator.clipboard.writeText(txt).then(() => showToast('Copiado!'));
}

// ── ITEM EDITOR MODAL ────────────────────────────────────────────
function setupItemEditor() {
  const modal = document.getElementById('item-editor-modal');
  const btnClose = document.getElementById('btn-close-editor');
  const btnCancel = document.getElementById('btn-cancel-editor');
  const btnSave = document.getElementById('btn-save-editor');
  const btnDelete = document.getElementById('btn-delete-item');
  const toggleEye = document.getElementById('toggle-edit-pass');

  if (btnClose) btnClose.onclick = closeItemEditor;
  if (btnCancel) btnCancel.onclick = closeItemEditor;

  if (toggleEye) {
    toggleEye.onclick = () => {
      const p = document.getElementById('edit-password');
      p.type = p.type === 'password' ? 'text' : 'password';
    };
  }

  if (btnSave) {
    btnSave.onclick = async () => {
      const id = document.getElementById('edit-item-id').value;
      const title = document.getElementById('edit-title').value.trim();
      const url = document.getElementById('edit-url').value.trim();
      const username = document.getElementById('edit-username').value.trim();
      const password = document.getElementById('edit-password').value;
      const notes = document.getElementById('edit-notes').value.trim();

      if (!title) {
        showToast('Informe o Nome do Serviço!');
        return;
      }

      if (id) {
        const item = vault.find(i => i.id === id);
        if (item) {
          item.title = title;
          item.url = url;
          item.username = username;
          item.password = password;
          item.notes = notes;
          item.updatedAt = Date.now();
        }
      } else {
        const newItem = {
          id: 'item_' + Date.now(),
          type: 'login',
          title,
          url,
          username,
          password,
          notes,
          createdAt: Date.now()
        };
        vault.unshift(newItem);
        selectedItemId = newItem.id;
      }

      await persistVaultChanges();
      closeItemEditor();
      renderItemsList();
      const current = vault.find(i => i.id === (id || selectedItemId));
      renderItemDetail(current);
      showToast('✅ Salvo com sucesso!');
    };
  }

  if (btnDelete) {
    btnDelete.onclick = async () => {
      const id = document.getElementById('edit-item-id').value;
      if (!id) return;
      if (confirm('Tem certeza que deseja excluir esta credencial?')) {
        vault = vault.filter(i => i.id !== id);
        selectedItemId = vault.length > 0 ? vault[0].id : null;
        await persistVaultChanges();
        closeItemEditor();
        renderItemsList();
        renderItemDetail(vault.length > 0 ? vault[0] : null);
        showToast('🗑️ Item excluído com sucesso!');
      }
    };
  }
}

function openItemEditor(item) {
  const modal = document.getElementById('item-editor-modal');
  const titleEl = document.getElementById('editor-modal-title');
  const btnDelete = document.getElementById('btn-delete-item');

  if (item) {
    titleEl.textContent = '✏️ Editar Item';
    document.getElementById('edit-item-id').value = item.id || '';
    document.getElementById('edit-title').value = item.title || '';
    document.getElementById('edit-url').value = item.url || '';
    document.getElementById('edit-username').value = item.username || '';
    document.getElementById('edit-password').value = item.password || '';
    document.getElementById('edit-password').type = 'password';
    document.getElementById('edit-notes').value = item.notes || '';
    btnDelete.style.display = 'block';
  } else {
    titleEl.textContent = '➕ Novo Item';
    document.getElementById('edit-item-id').value = '';
    document.getElementById('edit-title').value = currentDomain ? (currentDomain.charAt(0).toUpperCase() + currentDomain.slice(1)) : '';
    document.getElementById('edit-url').value = currentUrl || '';
    document.getElementById('edit-username').value = '';
    document.getElementById('edit-password').value = '';
    document.getElementById('edit-password').type = 'password';
    document.getElementById('edit-notes').value = '';
    btnDelete.style.display = 'none';
  }

  modal.style.display = 'flex';
  document.getElementById('edit-title').focus();
}

function closeItemEditor() {
  document.getElementById('item-editor-modal').style.display = 'none';
}

async function persistVaultChanges() {
  if (!masterKey) return;
  chrome.storage.local.get([STORAGE_KEY, 'safepass_cloud_token', 'safepass_cloud_user'], async (res) => {
    const stored = res[STORAGE_KEY];
    if (!stored) return;

    try {
      const parsed = JSON.parse(stored);
      const updatedPayload = await encryptData(vault, masterKey);
      const toStore = {
        salt: parsed.salt,
        verifier: parsed.verifier,
        payload: updatedPayload,
        updatedAt: Date.now()
      };

      chrome.storage.local.set({
        [STORAGE_KEY]: JSON.stringify(toStore),
        'safepass_unlocked_vault_cache': vault
      });

      let email = 'fbr4g4@gmail.com';
      try {
        if (res['safepass_cloud_user']) {
          const u = JSON.parse(res['safepass_cloud_user']);
          if (u.email) email = u.email;
        }
      } catch(e){}

      // 1. Envia push imediato para o servidor na nuvem
      const token = res['safepass_cloud_token'];
      const pushUrl = `https://4u.ia.br/app/safepass/index.php?action=push&email=${encodeURIComponent(email)}` + (token ? `&token=${encodeURIComponent(token)}` : '');
      fetch(pushUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vault_data: toStore, email })
      }).catch(()=>{});

      // 2. Notifica abas abertas do SafePass Web para atualização em tempo real se houver
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          if (tab.url && (tab.url.includes('4u.ia.br/app/safepass') || tab.url.includes('localhost:8080/app/safepass'))) {
            chrome.tabs.sendMessage(tab.id, { action: 'direct_inject_full_vault', vault_data: toStore }, () => {
              if (chrome.runtime.lastError) {}
            });
          }
        });
      });
    } catch(e){}
  });
}

// ── SETTINGS DRAWER ──────────────────────────────────────────────
function setupSettingsDrawer() {
  const btnMenu = document.getElementById('btn-menu-drawer');
  const btnClose = document.getElementById('btn-close-settings');
  const timeoutSelect = document.getElementById('select-vault-timeout');
  const btnTogglePin = document.getElementById('btn-toggle-pin-modal');
  const pinConfigBox = document.getElementById('pin-config-box');
  const btnCancelPin = document.getElementById('btn-cancel-pin');
  const btnSavePin = document.getElementById('btn-save-pin');

  if (btnMenu) btnMenu.onclick = openSettingsDrawer;
  if (btnClose) btnClose.onclick = closeSettingsDrawer;

  chrome.storage.local.get(['safepass_vault_timeout'], (res) => {
    if (res['safepass_vault_timeout'] && timeoutSelect) {
      timeoutSelect.value = res['safepass_vault_timeout'];
    }
  });

  if (timeoutSelect) {
    timeoutSelect.addEventListener('change', (e) => {
      const val = e.target.value;
      chrome.storage.local.set({ 'safepass_vault_timeout': val });
      if (val === 'never') {
        if (currentMasterPass) chrome.storage.local.set({ 'safepass_persistent_pass': currentMasterPass });
        showToast('🚫 Configurado para Nunca Bloquear!');
      } else {
        chrome.storage.local.remove('safepass_persistent_pass');
        showToast('⏱️ Tempo de bloqueio salvo: ' + timeoutSelect.options[timeoutSelect.selectedIndex].text);
      }
    });
  }

  if (btnTogglePin) {
    btnTogglePin.addEventListener('click', () => {
      chrome.storage.local.get(['safepass_has_pin'], (res) => {
        if (res['safepass_has_pin']) {
          if (confirm('Deseja remover o PIN de 6 dígitos configurado?')) {
            chrome.storage.local.remove(['safepass_has_pin', 'safepass_pin_salt', 'safepass_pin_payload'], () => {
              showToast('🗑️ PIN removido com sucesso!');
              updateSecurityUI();
            });
            return;
          }
        }
        pinConfigBox.style.display = pinConfigBox.style.display === 'none' ? 'block' : 'none';
        if (currentMasterPass) {
          const passInp = document.getElementById('input-pin-master-pass');
          if (passInp) passInp.value = currentMasterPass;
        }
        document.getElementById('input-new-pin').focus();
      });
    });
  }

  if (btnCancelPin) {
    btnCancelPin.addEventListener('click', () => {
      pinConfigBox.style.display = 'none';
    });
  }

  if (btnSavePin) {
    btnSavePin.addEventListener('click', async () => {
      const newPin = document.getElementById('input-new-pin').value.trim();
      const confirmPin = document.getElementById('input-confirm-pin').value.trim();
      const masterPass = document.getElementById('input-pin-master-pass').value || currentMasterPass;

      if (newPin.length !== 6 || !/^\d{6}$/.test(newPin)) return showToast('PIN deve ter exatamente 6 números!');
      if (newPin !== confirmPin) return showToast('Os PINs não coincidem!');
      if (!masterPass) return showToast('Digite sua Senha Mestra atual!');

      chrome.storage.local.get([STORAGE_KEY], async (res) => {
        const stored = res[STORAGE_KEY];
        if (!stored) return;

        try {
          const parsed = JSON.parse(stored);
          const salt = new Uint8Array(hexToBuffer(parsed.salt));
          const testKey = await deriveKey(masterPass, salt);
          const verifier = await decryptData(parsed.verifier, testKey);

          if (verifier !== 'VERIFIER_OK') return showToast('Senha Mestra incorreta!');

          const pinSalt = crypto.getRandomValues(new Uint8Array(16));
          const pinKey = await deriveKey(newPin, pinSalt);
          const pinPayload = await encryptData(masterPass, pinKey);

          chrome.storage.local.set({
            'safepass_has_pin': true,
            'safepass_pin_salt': bufferToHex(pinSalt),
            'safepass_pin_payload': pinPayload
          }, () => {
            showToast('✅ PIN de 6 dígitos ativado com sucesso!');
            pinConfigBox.style.display = 'none';
            document.getElementById('input-new-pin').value = '';
            document.getElementById('input-confirm-pin').value = '';
            updateSecurityUI();
          });
        } catch(e){
          showToast('Erro ao validar Senha Mestra.');
        }
      });
    });
  }

  // Drawer Password Generator
  const drawerGenPass = document.getElementById('drawer-gen-pass');
  const btnDrawerRegen = document.getElementById('btn-drawer-regen');
  const btnDrawerCopy = document.getElementById('btn-drawer-copy-gen');

  function updateDrawerPass() {
    if (drawerGenPass) drawerGenPass.value = generateQuickPass(20);
  }
  if (btnDrawerRegen) btnDrawerRegen.onclick = updateDrawerPass;
  if (btnDrawerCopy) btnDrawerCopy.onclick = () => copyText(drawerGenPass.value);
  updateDrawerPass();
}

function openSettingsDrawer() {
  updateSecurityUI();
  document.getElementById('settings-drawer').style.display = 'flex';
}
function closeSettingsDrawer() {
  document.getElementById('settings-drawer').style.display = 'none';
}

function updateSecurityUI() {
  chrome.storage.local.get(['safepass_has_pin'], (res) => {
    const desc = document.getElementById('pin-status-desc');
    const btn = document.getElementById('btn-toggle-pin-modal');
    if (res['safepass_has_pin']) {
      if (desc) desc.innerHTML = '<span style="color:var(--accent-emerald); font-weight:700;">● PIN Ativo (6 dígitos) 🟢</span>';
      if (btn) btn.textContent = 'Alterar / Remover PIN';
    } else {
      if (desc) desc.textContent = 'Nenhum PIN configurado';
      if (btn) btn.textContent = 'Configurar PIN de 6 Dígitos';
    }
  });
}

function generateQuickPass(len = 20) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}';
  const array = new Uint32Array(len);
  crypto.getRandomValues(array);
  let pass = '';
  for (let i = 0; i < len; i++) {
    pass += chars[array[i] % chars.length];
  }
  return pass;
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2200);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
