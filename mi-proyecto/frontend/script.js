// ─── Configuración central ───────────────────────────────────────────────────
const API = "http://localhost:5000/api";

// ─── Seguridad: escapar HTML para evitar XSS ─────────────────────────────────
// ⚠️  VULNERABILIDAD POTENCIAL: si no usaras esta función y pusieras
//     directamente innerHTML = datos_del_servidor, un atacante podría
//     inyectar <script> en el nombre de un producto y robar sesiones.
//     Siempre escapa los datos antes de insertarlos en el DOM.
function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ─── Obtener usuario logueado ─────────────────────────────────────────────────
async function getMe() {
  try {
    const res = await fetch(`${API}/me`, { credentials: "include" });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// ─── Renderizar barra de navegación según estado de sesión ───────────────────
async function renderNav() {
  const user = await getMe();
  const div  = document.getElementById("nav-links");
  if (!div) return;

  if (user) {
    div.innerHTML = `
      <span class="text-light me-2">Hola, ${escapeHtml(user.username)} | 💰 ${user.saldo.toFixed(2)} €</span>
      <a href="index.html"  class="btn btn-outline-light btn-sm">Catálogo</a>
      <a href="sell.html"   class="btn btn-warning btn-sm">Vender</a>
      <a href="cart.html"   class="btn btn-outline-light btn-sm">Mis compras</a>
      <button class="btn btn-danger btn-sm" onclick="logout()">Cerrar sesión</button>
    `;
  } else {
    div.innerHTML = `
      <a href="login.html"    class="btn btn-outline-light btn-sm">Iniciar sesión</a>
      <a href="register.html" class="btn btn-success btn-sm">Registrarse</a>
    `;
  }
}

// ─── Cerrar sesión ────────────────────────────────────────────────────────────
async function logout() {
  await fetch(`${API}/logout`, { method: "POST", credentials: "include" });
  location.href = "index.html";
}