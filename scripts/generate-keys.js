/**
 * generate-keys.js
 * ================
 * Genera el par de claves RSA-4096 (privada + pública) para el Portal de Noticias
 * y, si no existe un archivo .env, crea uno a partir de .env.example rellenando
 * automáticamente AES_KEY con 32 bytes criptográficamente aleatorios.
 *
 * Uso:
 *   npm run genkeys
 *
 * Las claves se guardan en:
 *   keys/private.pem  ← NUNCA commitear; en .gitignore
 *   keys/public.pem   ← Puede distribuirse libremente
 *
 * La clave privada se escribe con permisos 0o600 (solo lectura del propietario)
 * en sistemas Unix/Linux/macOS.  En Windows no hay una API POSIX equivalente,
 * pero el archivo se crea dentro de `keys/`, que el .gitignore excluye.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const KEYS_DIR = path.join(ROOT, 'keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'public.pem');
const ENV_PATH = path.join(ROOT, '.env');
const ENV_EXAMPLE_PATH = path.join(ROOT, '.env.example');

// ── 1. Crear directorio de claves ──────────────────────────────────────────
fs.mkdirSync(KEYS_DIR, { recursive: true });

// ── 2. Generar par RSA-4096 ────────────────────────────────────────────────
console.log('[genkeys] Generando par de claves RSA-4096 (esto puede tardar unos segundos)…');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { encoding: 'utf8', mode: 0o600 });
fs.writeFileSync(PUBLIC_KEY_PATH,  publicKey,  { encoding: 'utf8', mode: 0o644 });

console.log(`[genkeys] ✓ Clave privada guardada en: ${PRIVATE_KEY_PATH}`);
console.log(`[genkeys] ✓ Clave pública  guardada en: ${PUBLIC_KEY_PATH}`);

// ── 3. Generar AES_KEY de 32 bytes aleatorios ──────────────────────────────
const aesKey = crypto.randomBytes(32).toString('hex');
console.log(`\n[genkeys] ✓ AES_KEY generada: ${aesKey}`);

// ── 4. Actualizar .env ─────────────────────────────────────────────────────
let envContent = '';

if (fs.existsSync(ENV_PATH)) {
  envContent = fs.readFileSync(ENV_PATH, 'utf8');
} else if (fs.existsSync(ENV_EXAMPLE_PATH)) {
  envContent = fs.readFileSync(ENV_EXAMPLE_PATH, 'utf8');
  console.log('[genkeys] .env no encontrado; copiando desde .env.example');
}

// Reemplaza o agrega AES_KEY
if (/^AES_KEY\s*=/m.test(envContent)) {
  envContent = envContent.replace(/^AES_KEY\s*=.*/m, `AES_KEY=${aesKey}`);
} else {
  envContent += `\n# Clave simétrica AES-256 (generada por npm run genkeys)\nAES_KEY=${aesKey}\n`;
}

// Reemplaza o agrega RSA_PRIVATE_KEY_PATH (rutas relativas para portabilidad)
const privPathRel = 'keys/private.pem';
const pubPathRel  = 'keys/public.pem';

if (/^RSA_PRIVATE_KEY_PATH\s*=/m.test(envContent)) {
  envContent = envContent.replace(/^RSA_PRIVATE_KEY_PATH\s*=.*/m, `RSA_PRIVATE_KEY_PATH=${privPathRel}`);
} else {
  envContent += `\n# Rutas del par RSA (generadas por npm run genkeys)\nRSA_PRIVATE_KEY_PATH=${privPathRel}\n`;
}

if (/^RSA_PUBLIC_KEY_PATH\s*=/m.test(envContent)) {
  envContent = envContent.replace(/^RSA_PUBLIC_KEY_PATH\s*=.*/m, `RSA_PUBLIC_KEY_PATH=${pubPathRel}`);
} else {
  envContent += `RSA_PUBLIC_KEY_PATH=${pubPathRel}\n`;
}

fs.writeFileSync(ENV_PATH, envContent, 'utf8');
console.log(`[genkeys] ✓ .env actualizado con AES_KEY y rutas RSA.\n`);

console.log('────────────────────────────────────────────────────────────────');
console.log('Próximos pasos:');
console.log('  1. Revisa el archivo .env y configura el resto de variables.');
console.log('  2. Asegúrate de que keys/ esté en .gitignore (ya incluido).');
console.log('  3. Inicia el servidor con: npm start');
console.log('────────────────────────────────────────────────────────────────');

