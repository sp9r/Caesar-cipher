'use strict';

(() => {
  const FORMAT_PREFIX = 'CC1';
  const PBKDF2_ITERATIONS = 600000;
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const MIN_NEW_KEY_LENGTH = 12;
  const MAX_KEY_LENGTH = 1024;
  const MAX_PLAINTEXT_LENGTH = 8192;
  const MAX_INPUT_LENGTH = 32768;
  const AAD = new TextEncoder().encode(FORMAT_PREFIX);

  const form = document.getElementById('cipherForm');
  const input = document.getElementById('password');
  const keyInput = document.getElementById('key');
  const result = document.getElementById('result');
  const copyButton = document.getElementById('copyButton');
  const status = document.getElementById('status');
  const inputLabel = document.getElementById('inputLabel');

  function setStatus(message, kind = '') {
    status.textContent = message;
    status.className = 'status';
    if (kind) {
      status.classList.add(kind);
    }
  }

  function assertCryptoAvailable() {
    if (!window.isSecureContext || !globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
      throw new Error('安全な暗号機能を利用できません。HTTPSで開いてください。');
    }
  }

  function bytesToBase64Url(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  function base64UrlToBytes(value) {
    if (!/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new Error('暗号文の形式が不正です。');
    }

    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (normalized.length % 4)) % 4);

    let binary;
    try {
      binary = atob(normalized + padding);
    } catch {
      throw new Error('暗号文の形式が不正です。');
    }

    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function deriveAesKey(passphrase, salt) {
    const material = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      material,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptText(plaintext, passphrase) {
    if (plaintext.length === 0) {
      throw new Error('暗号化する文字列を入力してください。');
    }
    if (plaintext.length > MAX_PLAINTEXT_LENGTH) {
      throw new Error(`暗号化する文字列は ${MAX_PLAINTEXT_LENGTH} 文字以内にしてください。`);
    }
    if (passphrase.length < MIN_NEW_KEY_LENGTH) {
      throw new Error(`新規暗号化の鍵は ${MIN_NEW_KEY_LENGTH} 文字以上にしてください。`);
    }
    if (passphrase.length > MAX_KEY_LENGTH) {
      throw new Error('鍵が長すぎます。');
    }

    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const key = await deriveAesKey(passphrase, salt);
    const plaintextBytes = new TextEncoder().encode(plaintext);

    const ciphertextBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: AAD,
        tagLength: 128
      },
      key,
      plaintextBytes
    );

    return [
      FORMAT_PREFIX,
      bytesToBase64Url(salt),
      bytesToBase64Url(iv),
      bytesToBase64Url(new Uint8Array(ciphertextBuffer))
    ].join('.');
  }

  async function decryptModern(payload, passphrase) {
    if (passphrase.length === 0 || passphrase.length > MAX_KEY_LENGTH) {
      throw new Error('鍵を確認してください。');
    }

    const parts = payload.split('.');
    if (parts.length !== 4 || parts[0] !== FORMAT_PREFIX) {
      throw new Error('暗号文の形式が不正です。');
    }

    const salt = base64UrlToBytes(parts[1]);
    const iv = base64UrlToBytes(parts[2]);
    const ciphertext = base64UrlToBytes(parts[3]);

    if (salt.length !== SALT_BYTES || iv.length !== IV_BYTES || ciphertext.length < 16) {
      throw new Error('暗号文の形式が不正です。');
    }

    const key = await deriveAesKey(passphrase, salt);

    try {
      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: AAD,
          tagLength: 128
        },
        key,
        ciphertext
      );

      return new TextDecoder('utf-8', { fatal: true }).decode(plaintextBuffer);
    } catch {
      throw new Error('復号に失敗しました。鍵が違うか、暗号文が改ざんされています。');
    }
  }

  function legacyKeyNumbers(key) {
    const numbers = [];

    for (const ch of key) {
      if (/[a-zA-Z]/.test(ch)) {
        numbers.push(ch.toLowerCase().charCodeAt(0) - 96);
      } else if (/[0-9]/.test(ch)) {
        numbers.push(Number.parseInt(ch, 10));
      }
    }

    return numbers;
  }

  function decryptLegacy(ciphertext, key) {
    const keyNumbers = legacyKeyNumbers(key);
    if (keyNumbers.length === 0) {
      throw new Error('旧形式の復号に使用できる鍵ではありません。');
    }

    let output = '';

    for (let i = 0; i < ciphertext.length; i += 1) {
      const ch = ciphertext[i];
      const shift = keyNumbers[i % keyNumbers.length];

      if (/[A-Z]/.test(ch)) {
        const code = (ch.charCodeAt(0) - 65 + shift) % 26;
        output += String.fromCharCode(code + 65);
      } else if (/[a-z]/.test(ch)) {
        const code = (ch.charCodeAt(0) - 97 + shift) % 26;
        output += String.fromCharCode(code + 97);
      } else if (/[0-9]/.test(ch)) {
        const digit = (Number.parseInt(ch, 10) + shift) % 10;
        output += digit.toString();
      } else {
        output += ch;
      }
    }

    return output;
  }

  function currentMode() {
    return document.querySelector('input[name="mode"]:checked')?.value ?? 'encrypt';
  }

  function updateModeUi() {
    const decrypting = currentMode() === 'decrypt';

    inputLabel.textContent = decrypting ? '暗号文' : '暗号化する文字列';
    input.placeholder = decrypting ? `${FORMAT_PREFIX}.… または旧形式` : '暗号化したい文字列';
    input.autocomplete = 'off';
    result.textContent = '---';
    copyButton.disabled = true;
    setStatus('');
  }

  async function processInput(event) {
    event.preventDefault();
    assertCryptoAvailable();

    const value = input.value;
    const passphrase = keyInput.value;
    const mode = currentMode();

    if (value.length === 0) {
      throw new Error(mode === 'encrypt' ? '暗号化する文字列を入力してください。' : '暗号文を入力してください。');
    }
    if (value.length > MAX_INPUT_LENGTH) {
      throw new Error('入力が長すぎます。');
    }

    result.textContent = '';
    copyButton.disabled = true;
    setStatus('処理中…');

    if (mode === 'encrypt') {
      const encrypted = await encryptText(value, passphrase);
      result.textContent = encrypted;
      copyButton.disabled = false;
      setStatus('AES-256-GCMで暗号化しました。');
      return;
    }

    if (value.startsWith(`${FORMAT_PREFIX}.`)) {
      const decrypted = await decryptModern(value, passphrase);
      result.textContent = decrypted;
      copyButton.disabled = false;
      setStatus('AES-256-GCMの暗号文を復号しました。');
      return;
    }

    const decrypted = decryptLegacy(value, passphrase);
    result.textContent = decrypted;
    copyButton.disabled = false;
    setStatus('旧方式の暗号文を互換モードで復号しました。新規暗号化には使用しません。', 'warning');
  }

  async function copyResult() {
    if (copyButton.disabled || result.textContent === '---' || result.textContent.length === 0) {
      return;
    }

    try {
      await navigator.clipboard.writeText(result.textContent);
      const original = copyButton.textContent;
      copyButton.textContent = 'コピー済み';
      window.setTimeout(() => {
        copyButton.textContent = original;
      }, 1200);
    } catch {
      setStatus('クリップボードへのコピーに失敗しました。', 'error');
    }
  }

  form.addEventListener('submit', (event) => {
    processInput(event).catch((error) => {
      result.textContent = '---';
      copyButton.disabled = true;
      setStatus(error instanceof Error ? error.message : '処理に失敗しました。', 'error');
    });
  });

  document.querySelectorAll('input[name="mode"]').forEach((radio) => {
    radio.addEventListener('change', updateModeUi);
  });

  copyButton.addEventListener('click', copyResult);
  updateModeUi();
})();
