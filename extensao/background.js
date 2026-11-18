// SafePass Background Service Worker - 100% Standalone Engine

const STORAGE_KEY = 'safepass_encrypted_vault';
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

async function decryptData(encrypted, key) {
  const iv = hexToBuffer(encrypted.iv);
  const ciphertext = hexToBuffer(encrypted.data);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, ciphertext);
  return JSON.parse(dec.decode(decrypted));
}

async function autoDecryptPersistentCache() {
  return new Promise((resolve) => {
    chrome.storage.local.get([
      STORAGE_KEY,
      'safepass_persistent_pass',
      'safepass_vault_timeout',
      'safepass_session_expires_at',
      'safepass_session_unlocked_pass'
    ], async (res) => {
      const stored = res[STORAGE_KEY];
      const persistentPass = res['safepass_persistent_pass'];
      const sessionPass = res['safepass_session_unlocked_pass'] || persistentPass;
      const sessionExpiresAt = res['safepass_session_expires_at'] || 0;
      const timeout = res['safepass_vault_timeout'] || '15min';

      const isSessionValid = (timeout === 'never') || (sessionExpiresAt && Date.now() < sessionExpiresAt);

      if (stored && sessionPass && isSessionValid) {
        try {
          const parsed = JSON.parse(stored);
          const salt = new Uint8Array(hexToBuffer(parsed.salt));
          const key = await deriveKey(sessionPass, salt);
          const test = await decryptData(parsed.verifier, key);
          if (test === 'VERIFIER_OK') {
            const vault = await decryptData(parsed.payload, key);
            chrome.storage.local.set({ 'safepass_unlocked_vault_cache': vault }, () => {
              resolve(vault);
            });
            return;
          }
        } catch(e) {}
      }
      resolve(null);
    });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  autoDecryptPersistentCache();
});

if (chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(() => {
    autoDecryptPersistentCache();
  });
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

  if (item.title && item.title.toLowerCase().includes(targetBase)) return true;

  return false;
}

// Listener para mensagens da extensão
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'save_credential') {
    const cred = request.data;
    if (!cred || !cred.password) {
      sendResponse({ success: false, error: 'Credenciais inválidas' });
      return true;
    }

    chrome.storage.local.get(['safepass_pending_vault_items', 'safepass_unlocked_vault_cache'], (res) => {
      let pending = res['safepass_pending_vault_items'] || [];
      let cache = res['safepass_unlocked_vault_cache'] || [];

      pending = pending.filter(p => !(p.url === cred.url && p.username === cred.username));
      cache = cache.filter(p => !(p.url === cred.url && p.username === cred.username));

      const newItem = {
        id: 'item_' + Date.now(),
        type: 'login',
        title: cred.title || cred.domain || 'Login Web',
        url: cred.url,
        username: cred.username || '',
        password: cred.password,
        notes: 'Capturado automaticamente na extensão SafePass.',
        createdAt: Date.now()
      };

      // Evita duplicatas exatas na fila pendente
      const exists = pending.some(p => p.username === newItem.username && p.password === newItem.password && p.title === newItem.title);
      if (!exists) {
        pending.unshift(newItem);
        cache.unshift(newItem);
      }

      chrome.storage.local.set({
        'safepass_pending_vault_items': pending,
        'safepass_unlocked_vault_cache': cache
      }, () => {
        try {
          if (pending.length > 0) {
            chrome.action.setBadgeText({ text: String(pending.length) });
            chrome.action.setBadgeBackgroundColor({ color: '#6d4aff' });
          } else {
            chrome.action.setBadgeText({ text: '' });
          }
        } catch(e){}

        // Notifica abas ativas do SafePass Web se estiverem abertas (opcional)
        chrome.tabs.query({}, (tabs) => {
          tabs.forEach(tab => {
            if (tab.url && (tab.url.includes('4u.ia.br/app/safepass') || tab.url.includes('localhost:8080/app/safepass'))) {
              chrome.tabs.sendMessage(tab.id, { action: 'direct_inject_pending', item: newItem }, () => {
                if (chrome.runtime.lastError) {}
              });
            }
          });
        });

        sendResponse({ success: true, count: pending.length });
      });
    });
    return true;
  } else if (request.action === 'get_matched_logins') {
    const domain = (request.domain || '').replace(/^www\./i, '').toLowerCase();

    chrome.storage.local.get(['safepass_pending_vault_items', 'safepass_unlocked_vault_cache'], async (res) => {
      let pending = res['safepass_pending_vault_items'] || [];
      let cache = res['safepass_unlocked_vault_cache'] || [];

      // Se o cache local estiver vazio, tenta auto-descriptografar se a sessão for persistente
      if (cache.length === 0) {
        const decrypted = await autoDecryptPersistentCache();
        if (decrypted && Array.isArray(decrypted)) {
          cache = decrypted;
        }
      }

      const matches = [];
      const addedKeys = new Set();

      // 1. Busca no cache de senhas desbloqueadas
      cache.forEach(item => {
        if ((!item.type || item.type === 'login' || item.password) && isDomainMatch(item, domain)) {
          const key = (item.username || '') + '|' + (item.password || '');
          if (!addedKeys.has(key)) {
            addedKeys.add(key);
            matches.push(item);
          }
        }
      });

      // 2. Busca também nas pendentes recém-salvas
      pending.forEach(item => {
        if ((!item.type || item.type === 'login' || item.password) && isDomainMatch(item, domain)) {
          const key = (item.username || '') + '|' + (item.password || '');
          if (!addedKeys.has(key)) {
            addedKeys.add(key);
            matches.push(item);
          }
        }
      });

      // 3. Fallback: se ainda não achou e houver aba web aberta, consulta a aba
      if (matches.length === 0) {
        chrome.tabs.query({}, (tabs) => {
          const webTab = tabs.find(tab => tab.url && (tab.url.includes('4u.ia.br/app/safepass') || tab.url.includes('localhost:8080/app/safepass')));
          if (webTab) {
            chrome.tabs.sendMessage(webTab.id, { action: 'query_matches', domain }, (webRes) => {
              if (chrome.runtime.lastError) {
                sendResponse({ logins: [] });
                return;
              }
              if (webRes && webRes.logins && webRes.logins.length > 0) {
                chrome.storage.local.set({ 'safepass_unlocked_vault_cache': webRes.logins });
                sendResponse({ logins: webRes.logins });
              } else {
                sendResponse({ logins: [] });
              }
            });
          } else {
            sendResponse({ logins: [] });
          }
        });
      } else {
        sendResponse({ logins: matches });
      }
    });
    return true;
  }
});
