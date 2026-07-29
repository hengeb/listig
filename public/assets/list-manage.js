// templates/list/manage.latte — accept/reject moderation items via the API (see
// CLAUDE.md "Moderation via UI"). Translated error strings can't live in this
// static file, so list/manage.latte writes them into #list-manage-i18n's data
// attributes instead; getCsrfToken() comes from the shared script.js, loaded
// first (see templates/layout.latte).

const listManageI18n = document.getElementById('list-manage-i18n')?.dataset ?? {};

async function apiPost(url) {
    const r = await fetch(url, { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() } });
    if (!r.ok) { alert((listManageI18n.errorPrefix ?? '') + (await r.json()).error); return; }
    location.reload();
}

async function apiDelete(url) {
    const r = await fetch(url, { method: 'DELETE', headers: { 'X-CSRF-Token': getCsrfToken() } });
    if (!r.ok) { alert(listManageI18n.errorGeneric ?? ''); return; }
    location.reload();
}
