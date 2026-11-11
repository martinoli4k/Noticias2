const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { authenticateToken } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { logAudit, getClientIp } = require('../middleware/audit');
const {
  sanitizeInput,
  isValidText,
  MAX_TITULO,
  MAX_CONTENIDO,
  MAX_CATEGORIA,
  MAX_URL
} = require('../middleware/sanitizer');
const { subirImagen, eliminarImagenSinUso, UPLOAD_DIR } = require('../middleware/upload');
const { encrypt, decrypt, isEncrypted, signArticle, verifyArticle } = require('../services/crypto.service');
const path = require('path');
const fs = require('fs');

router.use(sanitizeInput);

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de cifrado / descifrado
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Descifra el título y el contenido de una fila de noticia proveniente de la BD.
 * Si algún campo no está cifrado (p.ej. en entorno sin AES_KEY) se devuelve tal cual.
 *
 * @param {object} row  Fila sin procesar de la BD.
 * @returns {object}    Fila con titulo y contenido descifrados.
 */
function decryptNews(row) {
  if (!row) return row;
  try {
    return {
      ...row,
      titulo:   isEncrypted(row.titulo)   ? decrypt(row.titulo)   : row.titulo,
      contenido: isEncrypted(row.contenido) ? decrypt(row.contenido) : row.contenido
    };
  } catch (err) {
    console.error(`[news] Error descifrando noticia id=${row.id}:`, err.message);
    // Devolver el registro con un marcador para no romper la lista entera.
    return { ...row, titulo: '[Error de descifrado]', contenido: '[Error de descifrado]' };
  }
}

/**
 * Elimina autor_email de una noticia antes de enviarla al cliente.
 * El email solo se expone cuando existe una necesidad funcional y permiso explícito.
 */
function sanitizeNewsForPublic(row) {
  if (!row) return row;
  const { autor_email, firma_digital, ...rest } = row;
  return rest;
}

/**
 * Lectura de noticias.
 *
 * El acceso al contenido es un recurso protegido: se exige autenticación y el
 * permiso `noticias.leer` del rol. Ocultar el contenido en la interfaz no es la
 * medida de seguridad, por eso la validación se repite aquí en el servidor.
 */
router.get('/', authenticateToken, requirePermission('noticias.leer'), (req, res) => {
  const { categoria, search } = req.query;
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);

  try {
    let query = `
      SELECT n.id, n.titulo, n.contenido, n.categoria, n.imagen_url, n.id_autor,
             n.fecha_creacion, n.fecha_actualizacion, n.firma_digital,
             u.nombre AS autor_nombre, r.nombre_rol AS autor_rol
      FROM noticias n
      JOIN usuarios u ON n.id_autor = u.id
      JOIN roles r ON u.id_rol = r.id
      WHERE 1=1
    `;
    const params = [];

    if (categoria && categoria !== 'Todas') {
      query += ' AND n.categoria = ?';
      params.push(String(categoria).slice(0, MAX_CATEGORIA));
    }

    query += ' ORDER BY n.fecha_creacion DESC, n.id DESC LIMIT ?';
    params.push(limit);

    // Leer filas cifradas, descifrar y filtrar búsqueda en claro
    let rows = db.prepare(query).all(...params).map(decryptNews);

    if (search) {
      const term = String(search).slice(0, MAX_TITULO).toLowerCase();
      rows = rows.filter(r =>
        r.titulo.toLowerCase().includes(term) ||
        r.contenido.toLowerCase().includes(term)
      );
    }

    res.json(rows.map(sanitizeNewsForPublic));
  } catch (error) {
    console.error('Error al listar noticias:', error.message);
    res.status(500).json({ error: 'Error al consultar las noticias' });
  }
});

// Listar categorías con contador
router.get('/categorias', authenticateToken, requirePermission('noticias.leer'), (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT categoria, COUNT(*) as total
      FROM noticias
      GROUP BY categoria
      ORDER BY total DESC
    `).all();
    res.json(rows);
  } catch (error) {
    console.error('Error al obtener categorías:', error.message);
    res.status(500).json({ error: 'Error al consultar categorías' });
  }
});

// Obtener detalle de una noticia (con verificación de firma)
router.get('/:id', authenticateToken, requirePermission('noticias.leer'), (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Identificador de noticia inválido' });
  }

  try {
    const item = db.prepare(`
      SELECT n.id, n.titulo, n.contenido, n.categoria, n.imagen_url, n.id_autor,
             n.fecha_creacion, n.fecha_actualizacion, n.firma_digital,
             u.nombre AS autor_nombre, r.nombre_rol AS autor_rol
      FROM noticias n
      JOIN usuarios u ON n.id_autor = u.id
      JOIN roles r ON u.id_rol = r.id
      WHERE n.id = ?
    `).get(id);

    if (!item) {
      return res.status(404).json({ error: 'Noticia no encontrada' });
    }

    // Descifrar antes de verificar la firma (la firma cubre el texto en claro)
    const decrypted = decryptNews(item);

    // Verificar firma RSA-PSS
    const { valid, reason } = verifyArticle(
      { titulo: decrypted.titulo, contenido: decrypted.contenido, categoria: decrypted.categoria },
      item.firma_digital
    );

    // Responder con el artículo en claro + resultado de verificación (sin email)
    const response = sanitizeNewsForPublic(decrypted);
    response.firma = { valid, reason };

    res.json(response);
  } catch (error) {
    console.error('Error al obtener noticia:', error.message);
    res.status(500).json({ error: 'Error al consultar el detalle de la noticia' });
  }
});

/**
 * Valida el cuerpo común de creación y edición de una noticia.
 */
function validateNewsPayload(body) {
  const { titulo, contenido, categoria, imagen_url } = body;

  if (!isValidText(titulo, { min: 3, max: MAX_TITULO })) {
    return `El título debe tener entre 3 y ${MAX_TITULO} caracteres`;
  }
  if (!isValidText(contenido, { min: 10, max: MAX_CONTENIDO })) {
    return `El contenido debe tener entre 10 y ${MAX_CONTENIDO} caracteres`;
  }
  if (!isValidText(categoria, { min: 2, max: MAX_CATEGORIA })) {
    return `La categoría debe tener entre 2 y ${MAX_CATEGORIA} caracteres`;
  }
  if (imagen_url && !isValidText(imagen_url, { min: 1, max: MAX_URL })) {
    return 'La URL de la imagen no es válida';
  }
  return null;
}

/**
 * Comprueba el identificador de la ruta antes de aceptar la carga de un archivo.
 */
function validarIdNoticia(req, res, next) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Identificador de noticia inválido' });
  }
  next();
}

// Crear nueva noticia
router.post('/',
  authenticateToken,
  requirePermission('noticias.crear'),
  subirImagen,
  sanitizeInput,
  (req, res) => {
  const { titulo, contenido, categoria, imagen_url } = req.body;
  const ip = getClientIp(req);

  const invalid = validateNewsPayload(req.body);
  if (invalid) {
    if (req.imagenSubida) eliminarImagenSinUso(req.imagenSubida);
    return res.status(400).json({ error: invalid });
  }

  try {
    const defaultImage = req.imagenSubida
      || (imagen_url && imagen_url.trim() !== ''
        ? imagen_url
        : 'https://images.unsplash.com/photo-1585829365295-ab7cd400c167?auto=format&fit=crop&w=1200&q=80');

    // Firmar el artículo en claro ANTES de cifrar
    const firma = signArticle({ titulo, contenido, categoria });

    // Cifrar título y contenido con AES-256-GCM
    const tituloEnc   = encrypt(titulo);
    const contenidoEnc = encrypt(contenido);

    const insert = db.prepare(`
      INSERT INTO noticias (titulo, contenido, categoria, imagen_url, id_autor, fecha_creacion, firma_digital)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const now = new Date().toISOString();
    const result = insert.run(tituloEnc, contenidoEnc, categoria, defaultImage, req.user.id, now, firma);
    const newId = Number(result.lastInsertRowid);

    logAudit(req.user.id, `Publicación de Noticia #${newId}`, `Título: "${titulo}" | Categoría: ${categoria}`, ip);

    const created = db.prepare(`
      SELECT n.*, u.nombre AS autor_nombre, r.nombre_rol AS autor_rol
      FROM noticias n
      JOIN usuarios u ON n.id_autor = u.id
      JOIN roles r ON u.id_rol = r.id
      WHERE n.id = ?
    `).get(newId);

    res.status(201).json({
      message: 'Noticia publicada con éxito',
      noticia: sanitizeNewsForPublic(decryptNews(created))
    });
  } catch (error) {
    console.error('Error al crear noticia:', error.message);
    if (req.imagenSubida) eliminarImagenSinUso(req.imagenSubida);
    res.status(500).json({ error: 'Error interno al publicar la noticia' });
  }
});

// Editar noticia
router.put('/:id',
  authenticateToken,
  requirePermission('noticias.editar'),
  validarIdNoticia,
  subirImagen,
  sanitizeInput,
  (req, res) => {
  const id = Number(req.params.id);
  const ip = getClientIp(req);

  const invalid = validateNewsPayload(req.body);
  if (invalid) {
    if (req.imagenSubida) eliminarImagenSinUso(req.imagenSubida);
    return res.status(400).json({ error: invalid });
  }

  const { titulo, contenido, categoria, imagen_url } = req.body;

  try {
    const existing = db.prepare('SELECT * FROM noticias WHERE id = ?').get(id);
    if (!existing) {
      if (req.imagenSubida) eliminarImagenSinUso(req.imagenSubida);
      return res.status(404).json({ error: 'Noticia no encontrada' });
    }

    if (req.user.nombre_rol !== 'Administrador' && existing.id_autor !== req.user.id) {
      if (req.imagenSubida) eliminarImagenSinUso(req.imagenSubida);
      return res.status(403).json({ error: 'No tienes autorización para modificar una noticia redactada por otro usuario' });
    }

    const now = new Date().toISOString();
    const finalImage = req.imagenSubida || imagen_url || existing.imagen_url;

    // Firmar el artículo en claro y cifrar
    const firma       = signArticle({ titulo, contenido, categoria });
    const tituloEnc   = encrypt(titulo);
    const contenidoEnc = encrypt(contenido);

    db.prepare(`
      UPDATE noticias
      SET titulo = ?, contenido = ?, categoria = ?, imagen_url = ?, fecha_actualizacion = ?, firma_digital = ?
      WHERE id = ?
    `).run(tituloEnc, contenidoEnc, categoria, finalImage, now, firma, id);

    if (existing.imagen_url !== finalImage) {
      eliminarImagenSinUso(existing.imagen_url);
    }

    logAudit(req.user.id, `Edición de Noticia #${id}`, `Título: "${titulo}" | Categoría: ${categoria}`, ip);

    const updated = db.prepare(`
      SELECT n.*, u.nombre AS autor_nombre, r.nombre_rol AS autor_rol
      FROM noticias n
      JOIN usuarios u ON n.id_autor = u.id
      JOIN roles r ON u.id_rol = r.id
      WHERE n.id = ?
    `).get(id);

    res.json({
      message: 'Noticia actualizada con éxito',
      noticia: sanitizeNewsForPublic(decryptNews(updated))
    });
  } catch (error) {
    console.error('Error al editar noticia:', error.message);
    if (req.imagenSubida) eliminarImagenSinUso(req.imagenSubida);
    res.status(500).json({ error: 'Error interno al actualizar la noticia' });
  }
});

// Eliminar noticia
router.delete('/:id', authenticateToken, requirePermission('noticias.eliminar'), (req, res) => {
  const id = Number(req.params.id);
  const ip = getClientIp(req);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Identificador de noticia inválido' });
  }

  try {
    const existing = db.prepare('SELECT * FROM noticias WHERE id = ?').get(id);
    if (!existing) {
      return res.status(404).json({ error: 'Noticia no encontrada' });
    }

    if (req.user.nombre_rol !== 'Administrador' && existing.id_autor !== req.user.id) {
      return res.status(403).json({ error: 'No tienes autorización para eliminar una noticia de otro autor' });
    }

    db.prepare('DELETE FROM noticias WHERE id = ?').run(id);

    eliminarImagenSinUso(existing.imagen_url);

    // Descifrar solo el título para el mensaje de auditoría
    let tituloClaro = existing.titulo;
    try {
      if (isEncrypted(existing.titulo)) tituloClaro = decrypt(existing.titulo);
    } catch (_) { /* no crítico */ }

    logAudit(req.user.id, `Eliminación de Noticia #${id}`, `Título eliminado: "${tituloClaro}"`, ip);

    res.json({ message: 'Noticia eliminada satisfactoriamente', id });
  } catch (error) {
    console.error('Error al eliminar noticia:', error.message);
    res.status(500).json({ error: 'Error interno al eliminar la noticia' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Ruta protegida para servir imágenes subidas
// Solo usuarios autenticados con permiso noticias.leer pueden acceder.
// Separa el contenido restringido del contenido público estático.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/imagen/:filename',
  authenticateToken,
  requirePermission('noticias.leer'),
  (req, res) => {
    const filename = req.params.filename;

    // Validar que el nombre no contenga path traversal
    if (!filename || filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
      return res.status(400).json({ error: 'Nombre de archivo inválido' });
    }

    const filePath = path.join(UPLOAD_DIR, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).type('text/plain').send('Imagen no encontrada');
    }

    // Cabecera de seguridad: las imágenes no deben ejecutarse como scripts
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'private, max-age=604800');
    res.sendFile(filePath);
  }
);

module.exports = router;
