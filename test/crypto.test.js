/**
 * test/crypto.test.js
 * ===================
 * Suite de pruebas de integración para los mecanismos criptográficos.
 * Verifica el flujo completo:
 *   - AES-256-GCM: dato en claro → cifrado → descifrado correcto
 *   - RSA-PSS:     artículo → firma → verificación válida / inválida
 *   - Integración con la BD: las noticias se guardan cifradas y se leen descifradas
 */

'use strict';

const path = require('path');
const fs = require('fs');
const testDbPath = path.join(__dirname, 'test-crypto.sqlite');
if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
process.env.DB_PATH = testDbPath;

require('dotenv').config();

const assert = require('assert');
const {
  encrypt, decrypt, isEncrypted,
  signArticle, verifyArticle, getPublicKeyPem
} = require('../src/services/crypto.service');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MECANISMO 1: AES-256-GCM
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n[Mecanismo 1] AES-256-GCM – Cifrado Simétrico');

test('Cifrar y descifrar produce el texto original', () => {
  const original = 'Contenido sensible de la noticia universitaria 🔐';
  const cifrado = encrypt(original);
  const descifrado = decrypt(cifrado);
  assert.strictEqual(descifrado, original, 'El texto descifrado debe ser igual al original');
});

test('El texto cifrado tiene el formato iv:tag:ciphertext (hex)', () => {
  const cifrado = encrypt('texto de prueba');
  const partes = cifrado.split(':');
  assert.strictEqual(partes.length, 3, 'Debe tener exactamente 3 partes separadas por ":"');
  assert.match(partes[0], /^[0-9a-f]{24}$/, 'IV debe ser 12 bytes hex (24 chars)');
  assert.match(partes[1], /^[0-9a-f]{32}$/, 'Tag debe ser 16 bytes hex (32 chars)');
  assert.ok(partes[2].length > 0, 'El ciphertext no debe estar vacío');
});

test('Dos cifrados del mismo texto producen resultados distintos (IV aleatorio)', () => {
  const texto = 'texto idéntico';
  const c1 = encrypt(texto);
  const c2 = encrypt(texto);
  assert.notStrictEqual(c1, c2, 'Cada cifrado debe tener un IV único');
});

test('isEncrypted reconoce textos cifrados', () => {
  const cifrado = encrypt('hola');
  assert.ok(isEncrypted(cifrado), 'Debe reconocer texto cifrado');
  assert.ok(!isEncrypted('texto en claro'), 'No debe marcar texto en claro como cifrado');
  assert.ok(!isEncrypted('a:b'), 'No debe marcar strings de 2 partes como cifrado');
});

test('Modificar el ciphertext provoca error de autenticación GCM', () => {
  const cifrado = encrypt('dato importante');
  const partes = cifrado.split(':');
  partes[2] = partes[2].replace(/[0-9a-f]{2}$/, 'ff'); // alterar últimos bytes
  assert.throws(() => decrypt(partes.join(':')), /ERR_OSSL|bad decrypt|Unsupported state/, 
    'Dato alterado debe lanzar error');
});

// ─────────────────────────────────────────────────────────────────────────────
// MECANISMO 2: RSA-PSS / SHA-256
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n[Mecanismo 2] RSA-PSS/SHA-256 – Firma Asimétrica');

const articuloPrueba = {
  titulo: 'Foro Internacional de Ciberseguridad',
  contenido: 'Especialistas compartieron buenas prácticas en autenticación robusta.',
  categoria: 'Tecnología'
};

test('Clave pública RSA disponible (no nula)', () => {
  const pem = getPublicKeyPem();
  if (!pem) {
    console.warn('    ⚠ Claves RSA no generadas; ejecuta npm run genkeys para habilitar este test');
    return;
  }
  assert.ok(pem.includes('BEGIN PUBLIC KEY'), 'La clave pública debe estar en formato PEM SPKI');
});

test('signArticle genera una firma base64 no vacía', () => {
  const firma = signArticle(articuloPrueba);
  if (!firma) {
    console.warn('    ⚠ signArticle retornó null (claves RSA no disponibles)');
    return;
  }
  assert.ok(typeof firma === 'string' && firma.length > 100, 'La firma debe ser un string base64 largo');
});

test('verifyArticle válida firma correcta → valid: true', () => {
  const firma = signArticle(articuloPrueba);
  if (!firma) { console.warn('    ⚠ Saltado: sin claves RSA'); return; }
  const { valid, reason } = verifyArticle(articuloPrueba, firma);
  assert.ok(valid, `Verificación debe ser válida. Razón: ${reason}`);
});

test('verifyArticle detecta título alterado → valid: false', () => {
  const firma = signArticle(articuloPrueba);
  if (!firma) { console.warn('    ⚠ Saltado: sin claves RSA'); return; }
  const alterado = { ...articuloPrueba, titulo: 'Título ALTERADO por atacante' };
  const { valid } = verifyArticle(alterado, firma);
  assert.ok(!valid, 'Título alterado debe invalidar la firma');
});

test('verifyArticle detecta contenido alterado → valid: false', () => {
  const firma = signArticle(articuloPrueba);
  if (!firma) { console.warn('    ⚠ Saltado: sin claves RSA'); return; }
  const alterado = { ...articuloPrueba, contenido: 'Contenido manipulado' };
  const { valid } = verifyArticle(alterado, firma);
  assert.ok(!valid, 'Contenido alterado debe invalidar la firma');
});

test('verifyArticle con firma nula → valid: false', () => {
  const { valid } = verifyArticle(articuloPrueba, null);
  assert.ok(!valid, 'Firma nula debe retornar invalid');
});

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRACIÓN: flujo completo en BD
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n[Integración] Flujo completo Noticia → BD cifrada → Lectura descifrada');

test('Noticia insertada en BD tiene título y contenido cifrados', () => {
  const db = require('../src/database/db');
  const noticias = db.prepare('SELECT titulo, contenido FROM noticias LIMIT 1').all();
  if (noticias.length === 0) { console.warn('    ⚠ BD vacía'); return; }
  const { titulo, contenido } = noticias[0];
  assert.ok(isEncrypted(titulo), `titulo debe estar cifrado en BD. Valor: ${titulo.slice(0,30)}`);
  assert.ok(isEncrypted(contenido), 'contenido debe estar cifrado en BD');
});

test('Descifrar noticia de BD produce texto legible', () => {
  const db = require('../src/database/db');
  const noticias = db.prepare('SELECT titulo, contenido FROM noticias LIMIT 1').all();
  if (noticias.length === 0) { console.warn('    ⚠ BD vacía'); return; }
  const { titulo, contenido } = noticias[0];
  const tituloClaro   = isEncrypted(titulo)   ? decrypt(titulo)   : titulo;
  const contenidoClaro = isEncrypted(contenido) ? decrypt(contenido) : contenido;
  assert.ok(tituloClaro.length > 10, 'Título descifrado debe ser texto legible');
  assert.ok(contenidoClaro.length > 20, 'Contenido descifrado debe ser texto legible');
  assert.ok(!isEncrypted(tituloClaro), 'El texto descifrado no debe seguir el formato cifrado');
});

test('Noticia en BD tiene firma_digital RSA', () => {
  const db = require('../src/database/db');
  const noticias = db.prepare('SELECT firma_digital FROM noticias LIMIT 1').all();
  if (noticias.length === 0) { console.warn('    ⚠ BD vacía'); return; }
  const { firma_digital } = noticias[0];
  if (!firma_digital) { console.warn('    ⚠ firma_digital nula (claves RSA no disponibles)'); return; }
  assert.ok(typeof firma_digital === 'string' && firma_digital.length > 100, 'Firma debe ser base64 RSA larga');
});

test('Firma de noticia en BD se verifica correctamente', () => {
  const db = require('../src/database/db');
  const row = db.prepare('SELECT titulo, contenido, categoria, firma_digital FROM noticias LIMIT 1').get();
  if (!row || !row.firma_digital) { console.warn('    ⚠ Saltado'); return; }
  const titulo   = isEncrypted(row.titulo)   ? decrypt(row.titulo)   : row.titulo;
  const contenido = isEncrypted(row.contenido) ? decrypt(row.contenido) : row.contenido;
  const { valid, reason } = verifyArticle({ titulo, contenido, categoria: row.categoria }, row.firma_digital);
  assert.ok(valid, `Firma en BD debe ser válida. Razón: ${reason}`);
});

test('Simulación de ataque: alterar 1 carácter de noticia en BD invalida la firma', () => {
  const db = require('../src/database/db');
  const row = db.prepare('SELECT titulo, contenido, categoria, firma_digital FROM noticias LIMIT 1').get();
  if (!row || !row.firma_digital) { console.warn('    ⚠ Saltado'); return; }
  const titulo   = isEncrypted(row.titulo)   ? decrypt(row.titulo)   : row.titulo;
  const contenido = isEncrypted(row.contenido) ? decrypt(row.contenido) : row.contenido;
  const contenidoAlterado = contenido + ' [INYECCIÓN MALICIOSA]';
  const { valid } = verifyArticle({ titulo, contenido: contenidoAlterado, categoria: row.categoria }, row.firma_digital);
  assert.strictEqual(valid, false, 'La firma debe invalidarse al alterar el contenido');
});

test('Almacenamiento seguro: AES_KEY definida en entorno y par RSA en archivos protegidos', () => {
  assert.ok(process.env.AES_KEY, 'AES_KEY debe estar en variables de entorno');
  assert.match(process.env.AES_KEY, /^[0-9a-fA-F]{64}$/, 'AES_KEY debe ser de 32 bytes (64 hex chars)');
  const pem = getPublicKeyPem();
  assert.ok(pem && pem.includes('PUBLIC KEY'), 'Clave pública RSA debe estar disponible');
});

// ─────────────────────────────────────────────────────────────────────────────
// Resumen
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(60)}`);
console.log(`Resultado: ${passed} pasados, ${failed} fallados`);
if (failed > 0) {
  console.error('⚠ Algunos tests fallaron');
  process.exit(1);
} else {
  console.log('✓ Todos los tests criptográficos pasaron correctamente');
}

