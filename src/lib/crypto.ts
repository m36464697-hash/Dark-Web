function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function generateSecurityFingerprint(uid: string, email: string): Promise<string> {
  const digest = await sha256Hex(`${uid}:${email.toLowerCase()}:darkweb-vault-v1`);
  return digest.slice(0, 32).toUpperCase();
}

export async function deriveInviteId(email: string): Promise<string> {
  const digest = await sha256Hex(`invite:${email.trim().toLowerCase()}`);
  return `inv_${digest.slice(0, 28)}`;
}

async function deriveAesKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 250_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export interface EncryptedBundle {
  ciphertext: string;
  iv: string;
  salt: string;
  integrityHash: string;
}

export async function encryptPayload(plaintext: string, passphrase: string): Promise<EncryptedBundle> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveAesKey(passphrase, salt);
  const encoded = new TextEncoder().encode(plaintext);

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    encoded
  );

  const ciphertext = toBase64(new Uint8Array(encryptedBuffer));
  const ivB64 = toBase64(iv);
  const saltB64 = toBase64(salt);
  const integrityHash = await sha256Hex(`${ciphertext}:${ivB64}:${saltB64}`);

  return {
    ciphertext,
    iv: ivB64,
    salt: saltB64,
    integrityHash,
  };
}

export async function decryptPayload(
  ciphertextB64: string,
  ivB64: string,
  saltB64: string,
  passphrase: string
): Promise<string> {
  const iv = fromBase64(ivB64);
  const salt = fromBase64(saltB64);
  const ciphertext = fromBase64(ciphertextB64);
  const key = await deriveAesKey(passphrase, salt);

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    ciphertext as BufferSource
  );

  return new TextDecoder().decode(decryptedBuffer);
}

export function generateValidDocId(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${prefix}_${Date.now()}_${hex}`;
}
