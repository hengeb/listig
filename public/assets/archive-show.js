// templates/archive/show.latte — "load external images" and HTML/plain-text
// toggle buttons, both of which reload the sandboxed iframe with a different
// query string rather than mutating its content directly (see CLAUDE.md
// "Archive viewer"); deleteArchivedMail() for the owner-only delete button.
// getCsrfToken() comes from the shared script.js, loaded first (see
// templates/layout.latte).

const archiveShowI18n = document.getElementById('archive-show-i18n')?.dataset ?? {};

async function deleteArchivedMail() {
    if (!confirm(archiveShowI18n.confirmDelete ?? '')) {
        return;
    }
    const r = await fetch(archiveShowI18n.deleteUrl, { method: 'DELETE', headers: { 'X-CSRF-Token': getCsrfToken() } });
    if (!r.ok) {
        alert(archiveShowI18n.errorGeneric ?? '');
        return;
    }
    location.href = archiveShowI18n.archiveIndexUrl;
}

function loadImages(btn) {
    const frame = document.getElementById('archive-frame');
    const url = new URL(frame.src, location.origin);
    url.searchParams.set('loadImages', '1');
    frame.src = url.toString();
    btn.closest('.notice').remove();
}

function setView(view) {
    const frame = document.getElementById('archive-frame');
    const url = new URL(frame.src, location.origin);
    url.searchParams.set('view', view);
    frame.src = url.toString();
    document.getElementById('view-html-btn').classList.toggle('btn-primary', view === 'html');
    document.getElementById('view-html-btn').classList.toggle('btn-secondary', view !== 'html');
    document.getElementById('view-text-btn').classList.toggle('btn-primary', view === 'text');
    document.getElementById('view-text-btn').classList.toggle('btn-secondary', view !== 'text');
}
