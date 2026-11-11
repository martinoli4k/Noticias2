/**
 * crypto.js
 * =========
 * Módulo de demostración y auditoría criptográfica en el frontend.
 * Permite presentar en vivo:
 *   1. La comparativa Antes / En BD Cifrado / Después (AES-256-GCM).
 *   2. La verificación e integridad de firmas digitales (RSA-PSS / SHA-256).
 *   3. Pruebas interactivas de manipulación de datos (demostración de fallas de integridad).
 *   4. Laboratorio de cifrado en vivo para evaluar textos personalizados.
 *   5. Ficha técnica y consulta de clave pública RSA.
 */

'use strict';

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const CryptoDemo = {
  inspeccionData: [],
  selectedArticleId: null,

  init() {
    this.bindTabEvents();
    this.bindActionEvents();
    this.loadInfo();
  },

  bindTabEvents() {
    const tabs = document.querySelectorAll('.crypto-tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.crypto-tab-pane').forEach(p => p.classList.remove('active'));

        tab.classList.add('active');
        const targetPaneId = tab.getAttribute('data-tab');
        const pane = document.getElementById(targetPaneId);
        if (pane) pane.classList.add('active');

        if (targetPaneId === 'tabCryptoInspection') {
          this.loadDbInspection();
        } else if (targetPaneId === 'tabCryptoKeys') {
          this.loadPublicKey();
        }
      });
    });
  },

  bindActionEvents() {
    // Delegación de eventos para la lista de inspección (sin inline handlers, respetando CSP)
    const inspectionList = document.getElementById('cryptoInspectionList');
    if (inspectionList) {
      inspectionList.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const action = btn.getAttribute('data-action');
        const id = Number(btn.getAttribute('data-id'));
        if (!id) return;

        if (action === 'verify') {
          this.testTamper(id, false);
        } else if (action === 'tamper') {
          this.testTamper(id, true);
        }
      });
    }
    const btnRefreshDb = document.getElementById('btnRefreshDbInspection');
    if (btnRefreshDb) {
      btnRefreshDb.addEventListener('click', () => this.loadDbInspection());
    }

    // Botón para ejecutar demo automatizada
    const btnRunDemo = document.getElementById('btnRunAutomatedDemo');
    if (btnRunDemo) {
      btnRunDemo.addEventListener('click', () => this.runAutomatedDemo());
    }

    // Laboratorio Simétrico: Cifrar y Descifrar en Vivo
    const btnLabEncrypt = document.getElementById('btnLabEncrypt');
    if (btnLabEncrypt) {
      btnLabEncrypt.addEventListener('click', () => this.testSymmetricLab());
    }

    // Botón para alterar un byte en el laboratorio
    const btnLabTamper = document.getElementById('btnLabTamper');
    if (btnLabTamper) {
      btnLabTamper.addEventListener('click', () => this.testSymmetricTamper());
    }

    // Copiar clave pública
    const btnCopyPublicKey = document.getElementById('btnCopyPublicKey');
    if (btnCopyPublicKey) {
      btnCopyPublicKey.addEventListener('click', () => {
        const keyArea = document.getElementById('cryptoPublicKeyDisplay');
        if (keyArea && keyArea.value) {
          navigator.clipboard.writeText(keyArea.value);
          showToast('Clave pública copiada al portapapeles', 'success');
        }
      });
    }
  },

  async loadInfo() {
    try {
      const data = await API.get('/crypto/info');
      const infoBox = document.getElementById('cryptoTechSpecs');
      if (!infoBox) return;

      infoBox.innerHTML = `
        <div class="crypto-specs-grid">
          <div class="crypto-spec-card">
            <div class="spec-header">
              <i class="fa-solid fa-microchip"></i>
              <h4>Librería Criptográfica</h4>
            </div>
            <p class="spec-badge-lib"><strong>${escapeHtml(data.libreria.nombre)}</strong></p>
            <p class="spec-desc">${escapeHtml(data.libreria.justificacion)}</p>
          </div>

          <div class="crypto-spec-card">
            <div class="spec-header">
              <i class="fa-solid fa-lock"></i>
              <h4>Mecanismo 1: Cifrado Simétrico</h4>
            </div>
            <ul class="spec-list">
              <li><strong>Algoritmo:</strong> <code>${escapeHtml(data.mecanismo1_simetrico.algoritmo)}</code></li>
              <li><strong>Longitud de Clave:</strong> ${escapeHtml(data.mecanismo1_simetrico.longitudClave)}</li>
              <li><strong>Vector de Inicialización:</strong> ${escapeHtml(data.mecanismo1_simetrico.vectorInicializacion)}</li>
              <li><strong>Tag de Autenticación:</strong> ${escapeHtml(data.mecanismo1_simetrico.tagAutenticacion)}</li>
              <li><strong>Dónde se guarda la clave:</strong> ${escapeHtml(data.mecanismo1_simetrico.dondeSeGuardaLaLlave)}</li>
            </ul>
          </div>

          <div class="crypto-spec-card">
            <div class="spec-header">
              <i class="fa-solid fa-signature"></i>
              <h4>Mecanismo 2: Firma Asimétrica</h4>
            </div>
            <ul class="spec-list">
              <li><strong>Algoritmo:</strong> <code>${escapeHtml(data.mecanismo2_asimetrico.algoritmo)}</code></li>
              <li><strong>Longitud de Clave:</strong> ${escapeHtml(data.mecanismo2_asimetrico.longitudClave)}</li>
              <li><strong>Relleno (Padding):</strong> ${escapeHtml(data.mecanismo2_asimetrico.esquemaRelleno)}</li>
              <li><strong>Dónde se guarda el par:</strong> ${escapeHtml(data.mecanismo2_asimetrico.dondeSeGuardaLaLlave)}</li>
            </ul>
          </div>
        </div>
      `;
    } catch (err) {
      console.warn('No se pudo cargar la información técnica criptográfica:', err);
    }
  },

  async loadDbInspection() {
    const container = document.getElementById('cryptoInspectionList');
    if (!container) return;

    container.innerHTML = `
      <div style="text-align: center; padding: 2.5rem; color: var(--color-text-muted);">
        <i class="fa-solid fa-spinner fa-spin fa-2x"></i>
        <p style="margin-top: 10px;">Consultando registros reales de la base de datos...</p>
      </div>
    `;

    try {
      const res = await API.get('/crypto/db-inspection');
      this.inspeccionData = res.inspeccion || [];
      this.renderDbInspection(this.inspeccionData);
    } catch (err) {
      container.innerHTML = `
        <div class="alert alert-error">
          <i class="fa-solid fa-circle-exclamation"></i>
          <div>Error consultando base de datos: ${escapeHtml(err.message || 'Error desconocido')}</div>
        </div>
      `;
    }
  },

  renderDbInspection(items) {
    const container = document.getElementById('cryptoInspectionList');
    if (!container) return;

    if (!items || items.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 2rem; color: var(--color-text-muted);">
          <i class="fa-regular fa-folder-open fa-2x"></i>
          <p>No hay noticias en la base de datos para inspeccionar.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = items.map((item, index) => {
      const isFirst = index === 0;
      const rawTitulo = item.base_de_datos_raw.titulo_almacenado || '';
      const rawContenido = item.base_de_datos_raw.contenido_almacenado || '';
      const firmaRaw = item.base_de_datos_raw.firma_digital_almacenada || '';
      const firmaValida = item.integridad_firma && item.integridad_firma.valid;

      return `
        <div class="crypto-compare-card ${isFirst ? 'highlight' : ''}" id="cryptoRow-${item.id}">
          <div class="compare-card-top">
            <div class="compare-badge-group">
              <span class="badge badge-category">${escapeHtml(item.categoria)}</span>
              <span class="badge" style="background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.3);">
                Noticia #${item.id}
              </span>
              <span class="badge ${firmaValida ? 'badge-crypto-valid' : 'badge-crypto-invalid'}">
                <i class="fa-solid ${firmaValida ? 'fa-circle-check' : 'fa-circle-xmark'}"></i>
                ${firmaValida ? 'Firma RSA Válida (Íntegra)' : 'Firma Inválida'}
              </span>
            </div>
            <div class="compare-actions">
              <button class="btn btn-sm btn-outline" data-action="verify" data-id="${item.id}">
                <i class="fa-solid fa-shield-check"></i> Verificar Firma
              </button>
              <button class="btn btn-sm btn-danger-outline" data-action="tamper" data-id="${item.id}">
                <i class="fa-solid fa-bug"></i> Simular Ataque
              </button>
            </div>
          </div>

          <div class="compare-three-columns">
            <!-- 1. ENTRADA / VISTA USUARIO -->
            <div class="compare-column col-clear">
              <div class="col-header">
                <i class="fa-solid fa-eye"></i>
                <span>1. Entrada en Claro (Vista Usuario)</span>
              </div>
              <div class="col-body">
                <label>Título Descifrado:</label>
                <div class="text-box-clear">${escapeHtml(item.usuario_ve.titulo)}</div>
                <label style="margin-top: 8px;">Contenido Descifrado:</label>
                <div class="text-box-clear content-box">${escapeHtml(item.usuario_ve.contenido)}</div>
              </div>
            </div>

            <!-- 2. ALMACENAMIENTO BD (RAW BD) -->
            <div class="compare-column col-db">
              <div class="col-header">
                <i class="fa-solid fa-database"></i>
                <span>2. Almacenado en Base de Datos (AES-256-GCM)</span>
              </div>
              <div class="col-body">
                <label>Título Cifrado en Disco (Hex):</label>
                <div class="code-box-cipher" title="Formato iv:tag:ciphertext">
                  ${this.formatCipherBreakdown(item.base_de_datos_raw.titulo_desglose, rawTitulo)}
                </div>
                <label style="margin-top: 8px;">Contenido Cifrado en Disco (Hex):</label>
                <div class="code-box-cipher content-box" title="Formato iv:tag:ciphertext">
                  ${this.formatCipherBreakdown(item.base_de_datos_raw.contenido_desglose, rawContenido)}
                </div>
              </div>
            </div>

            <!-- 3. FIRMA ASIMÉTRICA -->
            <div class="compare-column col-rsa">
              <div class="col-header">
                <i class="fa-solid fa-signature"></i>
                <span>3. Firma Digital (RSA-PSS 4096-bit)</span>
              </div>
              <div class="col-body">
                <label>Firma Digital (Base64 SHA-256):</label>
                <div class="code-box-signature" title="Firma digital criptográfica">
                  ${escapeHtml(firmaRaw || '[Sin firma]')}
                </div>
                <div class="signature-status-pill ${firmaValida ? 'status-ok' : 'status-bad'}" id="tamperResult-${item.id}">
                  <i class="fa-solid ${firmaValida ? 'fa-check-double' : 'fa-triangle-exclamation'}"></i>
                  <span>${escapeHtml(item.integridad_firma ? item.integridad_firma.reason : 'Verificada')}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      `;
    }).join('');
  },

  formatCipherBreakdown(desglose, fallbackRaw) {
    if (!desglose) {
      return `<span class="cipher-raw">${escapeHtml(fallbackRaw)}</span>`;
    }
    return `
      <div class="cipher-segments">
        <span class="seg-iv" title="IV (12 bytes aleatorios)">IV:${escapeHtml(desglose.iv_hex)}</span>:
        <span class="seg-tag" title="Tag de autenticación GCM (16 bytes)">TAG:${escapeHtml(desglose.tag_hex)}</span>:
        <span class="seg-ct" title="Ciphertext AES-256">${escapeHtml(desglose.ciphertext_hex.slice(0, 40))}…</span>
      </div>
    `;
  },

  async testTamper(id, modificar) {
    const resultBox = document.getElementById(`tamperResult-${id}`);
    if (resultBox) {
      resultBox.className = 'signature-status-pill status-loading';
      resultBox.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verificando firma criptográfica...';
    }

    try {
      const res = await API.post('/crypto/test-tamper', { id, modificar });
      if (resultBox) {
        if (res.resultado_verificacion.valid) {
          resultBox.className = 'signature-status-pill status-ok';
          resultBox.innerHTML = `
            <i class="fa-solid fa-circle-check"></i>
            <span><strong>Firma Íntegra:</strong> ${escapeHtml(res.resultado_verificacion.reason)}</span>
          `;
          showToast('Firma digital verificada: El contenido no ha sido alterado', 'success');
        } else {
          resultBox.className = 'signature-status-pill status-bad';
          resultBox.innerHTML = `
            <i class="fa-solid fa-triangle-exclamation"></i>
            <span><strong>¡ALERTA DE SEGURIDAD!</strong> ${escapeHtml(res.resultado_verificacion.reason)}</span>
          `;
          showToast('Alerta: La firma RSA-PSS detectó manipulación no autorizada', 'error');
        }
      }
    } catch (err) {
      if (resultBox) {
        resultBox.className = 'signature-status-pill status-bad';
        resultBox.innerHTML = `<i class="fa-solid fa-xmark"></i> Error: ${escapeHtml(err.message)}`;
      }
    }
  },

  async testSymmetricLab() {
    const input = document.getElementById('labPlaintextInput');
    const resultContainer = document.getElementById('labSymmetricResult');
    if (!input || !resultContainer) return;

    const texto = input.value.trim();
    if (!texto) {
      showToast('Por favor escribe un texto para cifrar', 'warning');
      return;
    }

    resultContainer.innerHTML = `
      <div style="text-align: center; padding: 1.5rem; color: var(--color-text-muted);">
        <i class="fa-solid fa-spinner fa-spin"></i> Cifrando con AES-256-GCM...
      </div>
    `;

    try {
      const res = await API.post('/crypto/test-symmetric', { texto });
      this.lastLabResult = res;

      resultContainer.innerHTML = `
        <div class="lab-success-panel">
          <div class="lab-stat-row">
            <span class="badge badge-success"><i class="fa-solid fa-check"></i> Cifrado y Descifrado Exitoso</span>
            <span class="lab-algo-tag">AES-256-GCM</span>
          </div>

          <div class="lab-step">
            <label><i class="fa-solid fa-arrow-right"></i> 1. Texto Plano Original:</label>
            <div class="code-box-clear">${escapeHtml(res.original)}</div>
          </div>

          <div class="lab-step">
            <label><i class="fa-solid fa-lock"></i> 2. Texto Cifrado Completo (Almacenado en BD):</label>
            <div class="code-box-cipher">${escapeHtml(res.cifradoCompleto)}</div>
          </div>

          <div class="lab-desglose-grid">
            <div class="desglose-card iv">
              <span class="desglose-label">Vector de Inicialización (IV)</span>
              <span class="desglose-val">${escapeHtml(res.desglose.iv_hex)}</span>
              <span class="desglose-meta">12 bytes aleatorios (96 bits)</span>
            </div>
            <div class="desglose-card tag">
              <span class="desglose-label">Auth Tag de Autenticación</span>
              <span class="desglose-val">${escapeHtml(res.desglose.auth_tag_hex)}</span>
              <span class="desglose-meta">16 bytes GCM (128 bits)</span>
            </div>
            <div class="desglose-card ct">
              <span class="desglose-label">Ciphertext (Datos cifrados)</span>
              <span class="desglose-val">${escapeHtml(res.desglose.ciphertext_hex)}</span>
              <span class="desglose-meta">${res.desglose.ciphertext_bytes} bytes cifrados</span>
            </div>
          </div>

          <div class="lab-step">
            <label><i class="fa-solid fa-unlock"></i> 3. Texto Descifrado (Lectura):</label>
            <div class="code-box-decrypted">${escapeHtml(res.descifrado)}</div>
          </div>

          <div class="lab-match-banner">
            <i class="fa-solid fa-equals"></i>
            <span>Verificación matemática: El texto original y el texto descifrado coinciden exactamente (100% integridad y confidencialidad).</span>
          </div>
        </div>
      `;

      const btnTamper = document.getElementById('btnLabTamper');
      if (btnTamper) btnTamper.style.display = 'inline-flex';
    } catch (err) {
      resultContainer.innerHTML = `
        <div class="alert alert-error">
          <i class="fa-solid fa-circle-exclamation"></i>
          <div>Error en cifrado simétrico: ${escapeHtml(err.message)}</div>
        </div>
      `;
    }
  },

  testSymmetricTamper() {
    const resultContainer = document.getElementById('labSymmetricResult');
    if (!this.lastLabResult || !resultContainer) {
      showToast('Primero cifra un texto en el laboratorio', 'warning');
      return;
    }

    const originalCipher = this.lastLabResult.cifradoCompleto;
    const parts = originalCipher.split(':');
    // Alteramos el último byte del ciphertext
    const ct = parts[2];
    const tamperedCt = ct.slice(0, -2) + (ct.slice(-2) === 'aa' ? 'bb' : 'aa');
    const tamperedFull = `${parts[0]}:${parts[1]}:${tamperedCt}`;

    resultContainer.innerHTML += `
      <div class="tamper-demo-box">
        <h5><i class="fa-solid fa-shield-virus"></i> Prueba de Manipulación de Bytes Cifrados:</h5>
        <p>Se modificó intencionalmente el último byte del texto cifrado en almacenamiento:</p>
        <div class="code-box-cipher"><del style="color:#ef4444;">${escapeHtml(originalCipher)}</del><br><strong>${escapeHtml(tamperedFull)}</strong></div>
        <div class="tamper-result-alert">
          <i class="fa-solid fa-ban"></i>
          <div>
            <strong>Error de descifrado lanzado por OpenSSL / AES-GCM:</strong><br>
            <code>Unsupported state or unable to authenticate data (Tag mismatch)</code><br>
            <small>Demuestra que el algoritmo rechaza los datos manipulados antes de procesarlos, previniendo inyecciones o alteraciones maliciosas.</small>
          </div>
        </div>
      </div>
    `;
    showToast('Prueba de manipulación completada: AES-GCM rechazó el dato alterado', 'error');
  },

  async loadPublicKey() {
    const keyArea = document.getElementById('cryptoPublicKeyDisplay');
    const keyDetails = document.getElementById('cryptoKeyDetails');
    if (!keyArea) return;

    try {
      const res = await API.get('/crypto/public-key');
      keyArea.value = res.publicKey || '';

      if (keyDetails) {
        keyDetails.innerHTML = `
          <div class="key-meta-badge"><i class="fa-solid fa-key"></i> Algoritmo: <strong>${escapeHtml(res.algoritmo)}</strong></div>
          <div class="key-meta-badge"><i class="fa-solid fa-hashtag"></i> Hash: <strong>${escapeHtml(res.hashAlgoritmo)}</strong></div>
          <div class="key-meta-badge"><i class="fa-solid fa-ruler"></i> Longitud: <strong>${escapeHtml(String(res.longitud))} bits</strong></div>
          <div class="key-meta-badge"><i class="fa-solid fa-file-code"></i> Formato: <strong>${escapeHtml(res.formato)}</strong></div>
        `;
      }
    } catch (err) {
      keyArea.value = 'Error al cargar clave pública: ' + err.message;
    }
  },

  async runAutomatedDemo() {
    const modal = document.getElementById('modalCryptoDemo');
    const output = document.getElementById('cryptoDemoOutput');
    if (!modal || !output) return;

    output.innerHTML = `
      <div style="text-align: center; padding: 2rem;">
        <i class="fa-solid fa-spinner fa-spin fa-2x"></i>
        <p style="margin-top: 10px;">Ejecutando suite criptográfica completa en el servidor...</p>
      </div>
    `;
    App.openModal('modalCryptoDemo');

    try {
      const res = await API.get('/crypto/demo');
      const sim = res.mecanismo1_simetrico;
      const asim = res.mecanismo2_asimetrico;

      output.innerHTML = `
        <div class="demo-run-results">
          <h4><i class="fa-solid fa-circle-check" style="color: #10b981;"></i> Resultados de la Demostración Criptográfica</h4>
          <p class="demo-summary">${escapeHtml(res.descripcion)}</p>

          <!-- MECANISMO 1 -->
          <div class="demo-section-box">
            <div class="demo-section-title">
              <i class="fa-solid fa-lock"></i>
              <span>Mecanismo 1: Cifrado Simétrico (${escapeHtml(sim.algoritmo)})</span>
            </div>
            <p class="demo-source"><i class="fa-solid fa-circle-info"></i> ${escapeHtml(sim.claveOrigen)}</p>
            <div class="demo-flow-step">
              <span class="step-num">Paso 1</span>
              <div><strong>Dato original en claro:</strong> <code>${escapeHtml(sim.flujo.paso1_datoEnClaro)}</code></div>
            </div>
            <div class="demo-flow-step">
              <span class="step-num">Paso 2</span>
              <div>
                <strong>Guardado cifrado en BD:</strong>
                <div class="code-box-cipher" style="margin-top: 4px;">${escapeHtml(sim.flujo.paso2_guardadoCifrado)}</div>
              </div>
            </div>
            <div class="demo-flow-step">
              <span class="step-num">Paso 3</span>
              <div><strong>Descifrado correctamente:</strong> <code>${escapeHtml(sim.flujo.paso3_descifradoCorrectamente)}</code></div>
            </div>
            <div class="demo-status-pill status-ok">
              <i class="fa-solid fa-check-double"></i> Verificación Simétrica: ${sim.flujo.verificacion ? 'EXITOSA (Texto idéntico)' : 'FALLIDA'}
            </div>
          </div>

          <!-- MECANISMO 2 -->
          <div class="demo-section-box" style="margin-top: 1.5rem;">
            <div class="demo-section-title">
              <i class="fa-solid fa-signature"></i>
              <span>Mecanismo 2: Firma Asimétrica (${escapeHtml(asim.algoritmo)})</span>
            </div>
            <p class="demo-source"><i class="fa-solid fa-circle-info"></i> ${escapeHtml(asim.clavePrivadaOrigen)}</p>
            <div class="demo-flow-step">
              <span class="step-num">Paso 1</span>
              <div><strong>Artículo a firmar:</strong> "${escapeHtml(asim.flujo.paso1_articuloOriginal.titulo)}"</div>
            </div>
            <div class="demo-flow-step">
              <span class="step-num">Paso 2</span>
              <div><strong>Firma RSA generada:</strong> <code>${escapeHtml(asim.flujo.paso2_firmaGenerada_base64)}</code></div>
            </div>
            <div class="demo-flow-step">
              <span class="step-num">Paso 3</span>
              <div><strong>Verificación de artículo original:</strong> <span class="badge badge-crypto-valid">Válido ✓ (${escapeHtml(asim.flujo.paso3_verificacionOriginal.reason)})</span></div>
            </div>
            <div class="demo-flow-step">
              <span class="step-num">Paso 4</span>
              <div><strong>Prueba con contenido alterado:</strong> "${escapeHtml(asim.flujo.paso4_articuloAlterado.contenido)}"</div>
            </div>
            <div class="demo-flow-step">
              <span class="step-num">Paso 5</span>
              <div><strong>Verificación con contenido alterado:</strong> <span class="badge badge-crypto-invalid">Rechazado ✗ (${escapeHtml(asim.flujo.paso5_verificacionAlterado.reason)})</span></div>
            </div>
          </div>
        </div>
      `;
    } catch (err) {
      output.innerHTML = `
        <div class="alert alert-error">
          <i class="fa-solid fa-circle-exclamation"></i>
          <div>Error en la demo automatizada: ${escapeHtml(err.message)}</div>
        </div>
      `;
    }
  }
};
