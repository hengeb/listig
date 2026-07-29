// Listig — shared JS, loaded on every page from templates/layout.latte's <head>
// (see CLAUDE.md "Static assets"). Page-specific behavior lives in its own file
// (archive-index.js, archive-show.js, list-manage.js), loaded alongside this one.

function getCsrfToken() {
    return document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('PHPSESSID='))?.split('=')[1] ?? '';
}

async function listigLogout(event) {
    event.preventDefault();
    const r = await fetch('/_/api/logout', { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() } });
    // Usually "/_/login", but an OIDC session may be sent on to the IdP's own
    // logout page first — see AuthController::logout().
    const data = await r.json();
    location.href = data.redirectUrl || '/_/login';
}

// Server-rendered timestamps (archived_mail.mail_date etc.) are always UTC —
// converted here to the viewer's own local timezone/locale, since the server has
// no reliable way to know that. data-utc holds an ISO 8601 UTC string (with "Z");
// the element's own text content is the UTC fallback if JS is disabled.
document.querySelectorAll('[data-utc]').forEach(el => {
    const d = new Date(el.dataset.utc);
    if (!isNaN(d)) {
        el.textContent = d.toLocaleString();
    }
});
