/**
 * crypto.service.js
 * =================
 * Mecanismos criptográficos del Portal de Noticias.
 *
 * MECANISMO 1 – Cifrado simétrico (AES-256-GCM)
 * -----------------------------------------------
 * Protege el contenido sensible de las noticias (título y cuerpo) en la base
 * de datos.  El flujo completo es:
 *   1. El dato llega en claro desde el editor.
 *   2. Se cifra con AES-256-GCM antes de INSERT/UPDATE.
 *   3. Al leer de la BD se descifra transparentemente.
 *
 * La clave (32 bytes hex) vive en la variable de entorno AES_KEY; nunca se
 * almacena en el código fuente.  Un IV de 12 bytes aleatorio se genera por cada
 * operación de cifrado y se almacena junto al texto cifrado y el tag de
 * autenticación en el formato: <iv_hex>:<tag_hex>:<ciphertext_hex>
 *
 * MECANISMO 2 – Firma digital asimétrica (RSA-PSS / SHA-256)
 * -----------------------------------------------------------
 * Cada noticia recibe una firma digital creada con la clave privada RSA del
 * servidor al momento de publicarse o editarse.  La firma cubre los campos
 * título, contenido y categoría —la huella del artículo en claro— y se
 * almacena en la columna `firma_digital`.
 *
 * Cualquier lectura puede verificar la autenticidad e integridad del artículo
 * con la clave PÚBLICA, que se expone en /api/crypto/public-key sin exponer
 * ningún secreto.
 *
 * Las claves RSA se generan con el script npm run genkeys y se referencian
 * desde RSA_PRIVATE_KEY_PATH / RSA_PUBLIC_KEY_PATH en .env; los archivos de
 * clave nunca se hardcodean en el código fuente.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─────────────────────────────────────────────────────────────────────────────
// MECANISMO 1: AES-256-GCM (cifrado simétrico)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resuelve y valida la clave simétrica AES-256 desde la variable de entorno.
 * La clave debe ser una cadena hexadecimal de 64 caracteres (32 bytes).
 */
function resolveAesKey() {
  const raw = (process.env.AES_KEY || '').trim();

  if (!raw) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('AES_KEY es obligatoria en producción. Defínela en .env (64 hex chars = 32 bytes).');
    }
    // Desarrollo: genera una clave efímera con advertencia para facilitar el
    // arranque sin configuración, pero los datos cifrados en esta sesión no
    // podrán descifrarse tras un reinicio.
    console.warn(
      '[crypto] AES_KEY no configurada. Se usa clave efímera de desarrollo. '
      + 'Los datos cifrados se perderán al reiniciar. '
      + 'Genera una clave permanente con: npm run genkeys'
    );
    return crypto.randomBytes(32);
  }

  if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error('AES_KEY debe ser exactamente 64 caracteres hexadecimales (32 bytes). '
      + `Recibido: ${raw.length} caracteres.`);
  }

  return Buffer.from(raw, 'hex');
}

const AES_KEY = resolveAesKey();
const AES_ALGO = 'aes-256-gcm';
const IV_LENGTH = 12; // GCM recomienda 96 bits
const TAG_LENGTH = 16;

/**
 * Cifra un texto plano con AES-256-GCM.
 *
 * @param {string} plaintext  Texto a cifrar.
 * @returns {string}          Texto cifrado en formato "<iv>:<tag>:<ciphertext>" (todo hex).
 */
function encrypt(plaintext) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('encrypt() espera un string');
  }
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(AES_ALGO, AES_KEY, iv, { authTagLength: TAG_LENGTH });

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Descifra un texto cifrado con AES-256-GCM.
 *
 * @param {string} ciphertext  Texto en formato "<iv>:<tag>:<ciphertext>" (hex).
 * @returns {string}           Texto en claro.
 * @throws {Error}             Si el formato es incorrecto o la autenticación falla.
 */
function decrypt(ciphertext) {
  if (typeof ciphertext !== 'string') {
    throw new TypeError('decrypt() espera un string');
  }

  const parts = ciphertext.split(':');
  if (parts.length !== 3) {
    throw new Error('Formato de texto cifrado inválido (esperado iv:tag:data)');
  }

  const [ivHex, tagHex, dataHex] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const data = Buffer.from(dataHex, 'hex');

  if (iv.length !== IV_LENGTH || tag.length !== TAG_LENGTH) {
    throw new Error('IV o tag de autenticación con longitud incorrecta');
  }

  const decipher = crypto.createDecipheriv(AES_ALGO, AES_KEY, iv, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

/**
 * Indica si un valor parece estar ya cifrado con nuestro esquema
 * (evita doble cifrado al actualizar un campo que ya fue cifrado).
 *
 * @param {string} value
 * @returns {boolean}
 */
function isEncrypted(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split(':');
  if (parts.length !== 3) return false;
  return parts[0].length === IV_LENGTH * 2
    && parts[1].length === TAG_LENGTH * 2
    && /^[0-9a-fA-F]+$/.test(parts.join(''));
}

// ─────────────────────────────────────────────────────────────────────────────
// MECANISMO 2: RSA-PSS (firma asimétrica)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Carga la clave privada RSA desde la ruta especificada en RSA_PRIVATE_KEY_PATH.
 * Solo el proceso servidor la carga; el archivo debe tener permisos restrictivos.
 */
function loadPrivateKey() {
  const envPath = process.env.RSA_PRIVATE_KEY_PATH;
  const candidatePaths = [
    envPath ? path.resolve(envPath) : null,
    path.join(__dirname, '..', '..', 'keys', 'private.pem'),
    path.join(process.cwd(), 'keys', 'private.pem'),
    path.join(process.cwd(), 'Noticias2-master', 'keys', 'private.pem')
  ].filter(Boolean);

  for (const keyPath of candidatePaths) {
    if (fs.existsSync(keyPath)) {
      return fs.readFileSync(keyPath, 'utf8');
    }
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'Clave privada RSA no encontrada en ninguna de las rutas esperadas. '
      + 'Genera el par de claves con: npm run genkeys'
    );
  }
  console.warn(
    '[crypto] Clave privada RSA no encontrada en las rutas configuradas. '
    + 'Las firmas digitales estarán desactivadas hasta ejecutar: npm run genkeys'
  );
  return null;
}

/**
 * Carga la clave pública RSA desde la ruta especificada en RSA_PUBLIC_KEY_PATH.
 */
function loadPublicKey() {
  const envPath = process.env.RSA_PUBLIC_KEY_PATH;
  const candidatePaths = [
    envPath ? path.resolve(envPath) : null,
    path.join(__dirname, '..', '..', 'keys', 'public.pem'),
    path.join(process.cwd(), 'keys', 'public.pem'),
    path.join(process.cwd(), 'Noticias2-master', 'keys', 'public.pem')
  ].filter(Boolean);

  for (const keyPath of candidatePaths) {
    if (fs.existsSync(keyPath)) {
      return fs.readFileSync(keyPath, 'utf8');
    }
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'Clave pública RSA no encontrada en ninguna de las rutas esperadas. '
      + 'Genera el par de claves con: npm run genkeys'
    );
  }
  console.warn('[crypto] Clave pública RSA no encontrada en las rutas configuradas.');
  return null;
}

// Las claves se cargan una vez al arrancar; si no existen se opera en modo
// degradado (sin firma) en desarrollo.
let RSA_PRIVATE_KEY = null;
let RSA_PUBLIC_KEY = null;

try {
  RSA_PRIVATE_KEY = loadPrivateKey();
  RSA_PUBLIC_KEY = loadPublicKey();
} catch (err) {
  if (process.env.NODE_ENV === 'production') throw err;
  console.warn('[crypto] No se pudieron cargar las claves RSA:', err.message);
}

const RSA_ALGO = {
  key: null,            // se rellena al firmar/verificar
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
};

/**
 * Construye el mensaje canónico que se firma: una concatenación determinista
 * de los campos que definen el contenido de la noticia.
 * Cambiar cualquiera de estos campos invalida la firma.
 *
 * @param {object} noticia   { titulo, contenido, categoria }
 * @returns {string}
 */
function buildSignablePayload(noticia) {
  return [
    noticia.titulo   || '',
    noticia.contenido || '',
    noticia.categoria || ''
  ].join('|');
}

/**
 * Firma digitalmente una noticia con la clave privada RSA-PSS/SHA-256.
 *
 * @param {{ titulo: string, contenido: string, categoria: string }} noticia
 * @returns {string|null}  Firma en base64, o null si las claves no están disponibles.
 */
function signArticle(noticia) {
  if (!RSA_PRIVATE_KEY) return null;

  const payload = buildSignablePayload(noticia);
  const sign = crypto.createSign('SHA256');
  sign.update(payload, 'utf8');
  sign.end();

  return sign.sign({ ...RSA_ALGO, key: RSA_PRIVATE_KEY }, 'base64');
}

/**
 * Verifica la firma digital de una noticia con la clave pública RSA.
 *
 * @param {{ titulo: string, contenido: string, categoria: string }} noticia
 * @param {string} signature  Firma en base64.
 * @returns {{ valid: boolean, reason: string }}
 */
function verifyArticle(noticia, signature) {
  if (!RSA_PUBLIC_KEY) {
    return { valid: false, reason: 'Clave pública no disponible' };
  }
  if (!signature) {
    return { valid: false, reason: 'El artículo no tiene firma digital' };
  }

  try {
    const payload = buildSignablePayload(noticia);
    const verify = crypto.createVerify('SHA256');
    verify.update(payload, 'utf8');
    verify.end();

    const ok = verify.verify({ ...RSA_ALGO, key: RSA_PUBLIC_KEY }, signature, 'base64');
    return ok
      ? { valid: true, reason: 'Firma válida: artículo íntegro y auténtico' }
      : { valid: false, reason: 'Firma inválida: el contenido puede haber sido alterado' };
  } catch (err) {
    return { valid: false, reason: `Error al verificar: ${err.message}` };
  }
}

/**
 * Devuelve la clave pública en formato PEM para exponerla vía API.
 * No expone ningún secreto.
 *
 * @returns {string|null}
 */
function getPublicKeyPem() {
  return RSA_PUBLIC_KEY;
}

/**
 * Recarga las claves RSA desde disco (útil en pruebas tras generar el par).
 */
function reloadKeys() {
  try {
    RSA_PRIVATE_KEY = loadPrivateKey();
    RSA_PUBLIC_KEY = loadPublicKey();
  } catch (err) {
    console.warn('[crypto] Error recargando claves RSA:', err.message);
  }
}

module.exports = {
  // Simétrico
  encrypt,
  decrypt,
  isEncrypted,
  // Asimétrico
  signArticle,
  verifyArticle,
  getPublicKeyPem,
  buildSignablePayload,
  reloadKeys
};

