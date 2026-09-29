// templates/compose.latte — asks the server for the masked reply address of the
// entered recipient and opens the mail client with it (see ComposeController). The
// translated error string comes from #compose-i18n's data attributes; getCsrfToken()
// from the shared script.js.

const composeI18n = document.getElementById('compose-i18n')?.dataset ?? {};

document.getElementById('compose-form')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = document.getElementById('compose-error');
    errorEl.hidden = true;
    try {
        const r = await fetch('/_/api/compose/' + encodeURIComponent(composeI18n.list), {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken(), 'Content-Type': 'application/json' },
            body: JSON.stringify({ mail: document.getElementById('compose-mail').value }),
        });
        const data = await r.json();
        if (!r.ok) {
            throw new Error(data.error ?? composeI18n.errorGeneric);
        }
        location.href = data.mailto;
    } catch (e) {
        errorEl.textContent = e.message || composeI18n.errorGeneric;
        errorEl.hidden = false;
    }
});
