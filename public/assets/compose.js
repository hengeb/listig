// templates/compose.latte — asks the server for the masked reply address of the
// entered recipient and shows it in a dialog (see ComposeController): a mailto: link to
// open it in the default mail program, and a copy button for any other one. The translated
// strings come from #compose-i18n's data attributes; getCsrfToken() from the shared script.js.

const composeI18n = document.getElementById('compose-i18n')?.dataset ?? {};
const composeDialog = document.getElementById('compose-dialog');
const composeAddress = document.getElementById('compose-dialog-address');
const composeCopy = document.getElementById('compose-dialog-copy');

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
        composeAddress.href = data.mailto;
        composeAddress.textContent = data.mailto.replace(/^mailto:/, '');
        composeCopy.textContent = composeI18n.copy;
        composeDialog.showModal();
    } catch (e) {
        errorEl.textContent = e.message || composeI18n.errorGeneric;
        errorEl.hidden = false;
    }
});

composeCopy?.addEventListener('click', async () => {
    const address = composeAddress.textContent;
    try {
        await navigator.clipboard.writeText(address);
    } catch (e) {
        // No clipboard API (insecure context, old browser): select the address so Ctrl+C works.
        const range = document.createRange();
        range.selectNodeContents(composeAddress);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        if (!document.execCommand?.('copy')) {
            return;
        }
    }
    composeCopy.textContent = composeI18n.copied;
});

document.getElementById('compose-dialog-close')?.addEventListener('click', () => composeDialog.close());
