// templates/list/manage.latte — accept/reject moderation items via the API (see
// docs/architecture/moderation.md "Moderation via UI"). Translated error strings can't live in this
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

// Live refresh of the delivery queue and the bounces (#manage-live-container, filled by
// templates/list/manage-live.latte; GET /_/api/live/{list} returns the same fragment). While
// mails are queued (data-pending > 0) it polls every second or two, otherwise every 20 s; a
// hidden tab does not poll at all and refreshes once when it becomes visible again. The
// container is only touched when the fragment actually changed, and then it is patched node by
// node (listigMorph), not rebuilt — so nothing flickers and the scroll position stays. After a
// failed request it backs off (20 s, 40 s, ... up to a minute); a redirect (session over) or a
// 404 (no longer an owner) stops it.
const manageLive = document.getElementById('manage-live-container');
if (manageLive) {
    const FAST_MS = 1500;
    const SLOW_MS = 20000;
    const MAX_BACKOFF_MS = 60000;
    let timer = null;
    let failures = 0;
    let inFlight = false;
    let last = null; // the last fragment text from the server; null until the first fetch

    const pending = () => Number(manageLive.querySelector('.manage-live')?.dataset.pending ?? 0);
    const delay = () => failures > 0
        ? Math.min(MAX_BACKOFF_MS, SLOW_MS * 2 ** (failures - 1))
        : (pending() > 0 ? FAST_MS : SLOW_MS);

    const schedule = () => {
        clearTimeout(timer);
        if (!document.hidden) {
            timer = setTimeout(refreshLive, delay());
        }
    };

    async function refreshLive() {
        if (inFlight) {
            return;
        }
        inFlight = true;
        try {
            const r = await fetch(manageLive.dataset.url, { cache: 'no-store' });
            if (r.redirected || r.status === 404) {
                return; // logged out / not an owner any more: stop polling for good
            }
            if (!r.ok) {
                throw new Error('HTTP ' + r.status);
            }
            const html = (await r.text()).trim();
            failures = 0;
            if (html !== last) {
                // Patch, don't replace: unchanged nodes stay, so scroll position, text selection
                // and hover survive even a long bounce list (dom-morph.js).
                listigMorph(manageLive, html);
                last = html;
            }
        } catch (e) {
            failures++;
        } finally {
            inFlight = false;
        }
        schedule();
    }

    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            clearTimeout(timer);
        } else {
            refreshLive();
        }
    });
    schedule();
}
