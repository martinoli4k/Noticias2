/**
 * crypto.routes.js
 * ================
 * Endpoints relacionados con los mecanismos criptográficos del portal.
 *
 * GET  /api/crypto/public-key   → Devuelve la clave pública RSA en PEM (sin secretos).
 * GET  /api/crypto/demo         → Demuestra el flujo completo AES-256-GCM y RSA-PSS
 *                                 con datos de prueba para verificación académica.
 * POST /api/crypto/verify/:id   → Verifica la firma digital de una noticia específica.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { encrypt, decrypt, signArticle, verifyArticle, getPublicKeyPem } = require('../services/crypto.service');
const db = require('../database/db');

/**
 * GET /api/crypto/public-key
 * Expone la clave pública RSA para que cualquier cliente pueda verificar firmas.
 * No requiere autenticación (es información pública por definición).
 */
router.get('/public-key', (req, res) => {
  const pem = getPublicKeyPem();
  if (!pem) {
    return res.status(503).json({
      error: 'Clave pública RSA no disponible. Ejecuta: npm run genkeys'
    });
  }
  res.json({
    algoritmo: 'RSA-PSS',
    hashAlgoritmo: 'SHA-256',
    longitud: 4096,
    formato: 'SPKI PEM',
    publicKey: pem
  });
});

/**
 * GET /api/crypto/info
 * Información técnica sobre las librerías, algoritmos y almacenamiento de llaves.
 */
router.get('/info', (req, res) => {
  res.json({
    libreria: {
      nombre: 'Node.js crypto (nativo, basado en OpenSSL)',
      tipo: 'Módulo criptográfico estándar del lenguaje',
      justificacion: 'Se utilizó el módulo nativo crypto de Node.js porque está respaldado por OpenSSL, no requiere paquetes de terceros propensos a vulnerabilidades de la cadena de suministro, implementa algoritmos auditados internacionalmente (FIPS 140), cuenta con protección contra ataques de canal lateral (comparaciones en tiempo constante) y garantiza máximo rendimiento y estabilidad.'
    },
    mecanismo1_simetrico: {
      algoritmo: 'AES-256-GCM (Galois/Counter Mode)',
      longitudClave: '256 bits (32 bytes)',
      vectorInicializacion: 'IV aleatorio de 96 bits (12 bytes) por cada operación',
      tagAutenticacion: '128 bits (16 bytes)',
      formatoAlmacenamiento: '<iv_hex>:<tag_hex>:<ciphertext_hex>',
      dondeSeGuardaLaLlave: 'Variable de entorno AES_KEY en archivo protegido .env (nunca hardcodeada en el código fuente ni incluida en el repositorio git).',
      casoDeUso: 'Protección de confidencialidad e integridad de campos sensibles en la base de datos (título y cuerpo de noticias).'
    },
    mecanismo2_asimetrico: {
      algoritmo: 'RSA-PSS con hash criptográfico SHA-256',
      longitudClave: '4096 bits',
      esquemaRelleno: 'PSS (Probabilistic Signature Scheme)',
      dondeSeGuardaLaLlave: 'Clave privada en archivo keys/private.pem (permisos restringidos 0o600, excluida de git vía .gitignore). Clave pública en archivo keys/public.pem (distribuible libremente). Ambas rutas se resuelven mediante RSA_PRIVATE_KEY_PATH y RSA_PUBLIC_KEY_PATH en .env con respaldo automático a directorio local keys/.',
      casoDeUso: 'Garantía de autenticidad e integridad de las noticias publicadas, evitando falsificaciones y detectando cualquier alteración no autorizada de los datos.'
    }
  });
});

/**
 * GET /api/crypto/demo
 * Demuestra el flujo completo de ambos mecanismos criptográficos con datos
 * de prueba para verificación académica en vivo.
 */
router.get('/demo', (req, res) => {
  // ── Mecanismo 1: AES-256-GCM ──────────────────────────────────────────────
  const datoOriginal = 'Contenido sensible de prueba: investigación confidencial universitaria 🔐';

  const textoCifrado = encrypt(datoOriginal);
  const partes = textoCifrado.split(':');
  const datoDescifrado = decrypt(textoCifrado);

  const demoSimetrico = {
    algoritmo: 'AES-256-GCM',
    claveOrigen: 'Variable de entorno AES_KEY (32 bytes, nunca en código fuente)',
    flujo: {
      paso1_datoEnClaro: datoOriginal,
      paso2_guardadoCifrado: textoCifrado,
      estructura: {
        iv_hex:         partes[0],
        tag_hex:        partes[1],
        ciphertext_hex: partes[2]
      },
      paso3_descifradoCorrectamente: datoDescifrado,
      verificacion: datoOriginal === datoDescifrado
    }
  };

  // ── Mecanismo 2: RSA-PSS / SHA-256 ────────────────────────────────────────
  const articuloPrueba = {
    titulo:   'Artículo de demostración criptográfica',
    contenido: 'Este contenido está firmado digitalmente con RSA-PSS/SHA-256.',
    categoria: 'Tecnología'
  };

  const firma = signArticle(articuloPrueba);
  const verificacionCorrecta = verifyArticle(articuloPrueba, firma);

  // Verificación con contenido alterado (debe fallar)
  const articuloAlterado = { ...articuloPrueba, contenido: 'Contenido ALTERADO por atacante' };
  const verificacionFallida = verifyArticle(articuloAlterado, firma);

  const demoAsimetrico = {
    algoritmo: 'RSA-PSS / SHA-256 (clave de 4096 bits)',
    clavePrivadaOrigen: 'Archivo en RSA_PRIVATE_KEY_PATH (fuera del código fuente, permisos 0o600)',
    clavePublicaOrigen: 'Archivo en RSA_PUBLIC_KEY_PATH (puede distribuirse libremente)',
    flujo: {
      paso1_articuloOriginal: articuloPrueba,
      paso2_firmaGenerada_base64: firma ? firma.slice(0, 60) + '…' : null,
      paso3_verificacionOriginal: verificacionCorrecta,
      paso4_articuloAlterado: articuloAlterado,
      paso5_verificacionAlterado: verificacionFallida
    }
  };

  res.json({
    descripcion: 'Demostración de los dos mecanismos criptográficos del Portal de Noticias',
    mecanismo1_simetrico: demoSimetrico,
    mecanismo2_asimetrico: demoAsimetrico
  });
});

/**
 * GET /api/crypto/db-inspection
 * Inspecciona los registros reales de la base de datos SQLite y muestra
 * la comparativa antes/en BD/después del cifrado para la presentación en vivo.
 */
router.get('/db-inspection', (req, res) => {
  try {
    const { isEncrypted: isEnc } = require('../services/crypto.service');
    const rows = db.prepare(`
      SELECT n.id, n.titulo, n.contenido, n.categoria, n.firma_digital,
             n.fecha_creacion, u.nombre AS autor_nombre
      FROM noticias n
      JOIN usuarios u ON n.id_autor = u.id
      ORDER BY n.id ASC
    `).all();

    const comparativa = rows.map(row => {
      const estaCifradoTitulo = isEnc(row.titulo);
      const estaCifradoContenido = isEnc(row.contenido);

      const tituloDescifrado = estaCifradoTitulo ? decrypt(row.titulo) : row.titulo;
      const contenidoDescifrado = estaCifradoContenido ? decrypt(row.contenido) : row.contenido;

      let partesTitulo = null;
      if (estaCifradoTitulo) {
        const p = row.titulo.split(':');
        partesTitulo = { iv_hex: p[0], tag_hex: p[1], ciphertext_hex: p[2] };
      }

      let partesContenido = null;
      if (estaCifradoContenido) {
        const p = row.contenido.split(':');
        partesContenido = { iv_hex: p[0], tag_hex: p[1], ciphertext_hex: p[2] };
      }

      const verif = verifyArticle(
        { titulo: tituloDescifrado, contenido: contenidoDescifrado, categoria: row.categoria },
        row.firma_digital
      );

      return {
        id: row.id,
        autor: row.autor_nombre,
        categoria: row.categoria,
        fecha_creacion: row.fecha_creacion,
        // 1. Entrada / Vista usuario
        usuario_ve: {
          titulo: tituloDescifrado,
          contenido: contenidoDescifrado
        },
        // 2. Almacenamiento real en SQLite
        base_de_datos_raw: {
          titulo_almacenado: row.titulo,
          titulo_desglose: partesTitulo,
          contenido_almacenado: row.contenido,
          contenido_desglose: partesContenido,
          firma_digital_almacenada: row.firma_digital
        },
        // 3. Verificación de integridad asimétrica
        integridad_firma: verif
      };
    });

    res.json({
      total_noticias: comparativa.length,
      inspeccion: comparativa
    });
  } catch (error) {
    console.error('Error al inspeccionar BD:', error.message);
    res.status(500).json({ error: 'Error al inspeccionar base de datos' });
  }
});

/**
 * POST /api/crypto/test-symmetric
 * Permite al usuario/evaluador probar el cifrado y descifrado AES-256-GCM
 * con cualquier texto en vivo desde la interfaz.
 */
router.post('/test-symmetric', express.json(), (req, res) => {
  const texto = (req.body && typeof req.body.texto === 'string') ? req.body.texto.trim() : '';
  if (!texto) {
    return res.status(400).json({ error: 'Proporciona un campo "texto" para cifrar' });
  }

  try {
    const cifrado = encrypt(texto);
    const partes = cifrado.split(':');
    const descifrado = decrypt(cifrado);

    res.json({
      algoritmo: 'AES-256-GCM',
      original: texto,
      cifradoCompleto: cifrado,
      desglose: {
        iv_hex: partes[0],
        iv_bytes: partes[0].length / 2,
        auth_tag_hex: partes[1],
        auth_tag_bytes: partes[1].length / 2,
        ciphertext_hex: partes[2],
        ciphertext_bytes: partes[2].length / 2
      },
      descifrado: descifrado,
      exito: texto === descifrado
    });
  } catch (err) {
    res.status(500).json({ error: 'Error en prueba simétrica: ' + err.message });
  }
});

/**
 * POST /api/crypto/test-tamper
 * Demuestra en vivo la detección de alteraciones mediante la firma digital RSA-PSS.
 */
router.post('/test-tamper', express.json(), (req, res) => {
  const { id, modificar } = req.body || {};
  const noticiaId = Number(id);

  if (!Number.isInteger(noticiaId) || noticiaId <= 0) {
    return res.status(400).json({ error: 'ID de noticia inválido' });
  }

  try {
    const { isEncrypted: isEnc } = require('../services/crypto.service');
    const row = db.prepare(`
      SELECT n.id, n.titulo, n.contenido, n.categoria, n.firma_digital, u.nombre AS autor_nombre
      FROM noticias n
      JOIN usuarios u ON n.id_autor = u.id
      WHERE n.id = ?
    `).get(noticiaId);

    if (!row) {
      return res.status(404).json({ error: 'Noticia no encontrada' });
    }

    const titulo = isEnc(row.titulo) ? decrypt(row.titulo) : row.titulo;
    let contenido = isEnc(row.contenido) ? decrypt(row.contenido) : row.contenido;

    let fueModificado = false;
    if (modificar) {
      contenido = contenido + ' [TEXTO INYECTADO POR ATACANTE]';
      fueModificado = true;
    }

    const resultado = verifyArticle(
      { titulo, contenido, categoria: row.categoria },
      row.firma_digital
    );

    res.json({
      noticia_id: noticiaId,
      fue_modificado: fueModificado,
      contenido_probado: contenido,
      firma_utilizada: row.firma_digital ? row.firma_digital.slice(0, 50) + '…' : null,
      resultado_verificacion: resultado
    });
  } catch (error) {
    res.status(500).json({ error: 'Error en prueba de manipulación: ' + error.message });
  }
});

/**
 * GET /api/crypto/verify/:id
 * Verifica la firma digital de una noticia específica.
 * Requiere autenticación y permiso de lectura.
 */
router.get('/verify/:id', authenticateToken, requirePermission('noticias.leer'), (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'ID de noticia inválido' });
  }

  try {
    const { decrypt: dec, isEncrypted: isCiphered } = require('../services/crypto.service');

    const row = db.prepare(`
      SELECT n.id, n.titulo, n.contenido, n.categoria, n.firma_digital,
             n.fecha_creacion, u.nombre AS autor_nombre
      FROM noticias n
      JOIN usuarios u ON n.id_autor = u.id
      WHERE n.id = ?
    `).get(id);

    if (!row) {
      return res.status(404).json({ error: 'Noticia no encontrada' });
    }

    // Descifrar para verificar la firma (la firma cubre el texto en claro)
    const titulo   = isCiphered(row.titulo)   ? dec(row.titulo)   : row.titulo;
    const contenido = isCiphered(row.contenido) ? dec(row.contenido) : row.contenido;

    const resultado = verifyArticle(
      { titulo, contenido, categoria: row.categoria },
      row.firma_digital
    );

    res.json({
      id: row.id,
      autor: row.autor_nombre,
      fecha_creacion: row.fecha_creacion,
      firma_presente: Boolean(row.firma_digital),
      verificacion: resultado
    });
  } catch (error) {
    console.error('Error al verificar firma:', error.message);
    res.status(500).json({ error: 'Error interno al verificar la firma digital' });
  }
});

module.exports = router;

