// templates/archive/index.latte — thread toggle, per-thread expand/collapse, and
// the quick filter. Pure client-side, no network round-trips (see CLAUDE.md
// "Threading").

let flatMode = false;
let originalOrder = null;

function getTbody() { return document.getElementById('archive-tbody'); }

function toggleThreading() {
    const tbody = getTbody();
    const btn = document.getElementById('thread-toggle');
    if (!originalOrder) originalOrder = Array.from(tbody.rows);
    flatMode = !flatMode;
    btn.setAttribute('aria-pressed', String(!flatMode));

    if (flatMode) {
        const rows = Array.from(tbody.rows);
        rows.sort((a, b) => new Date(b.dataset.date) - new Date(a.dataset.date));
        rows.forEach(r => {
            r.classList.remove('reply-row', 'expanded');
            r.style.display = '';
            tbody.appendChild(r);
        });
        tbody.querySelectorAll('.thread-indent').forEach(el => { el.style.width = '0'; });
        tbody.querySelectorAll('.thread-expand').forEach(el => { el.style.display = 'none'; });
        tbody.querySelectorAll('[data-reply-count]').forEach(el => { el.style.display = 'none'; });
    } else {
        originalOrder.forEach(r => {
            tbody.appendChild(r);
            r.style.display = '';
            if (r.dataset.isThreadStart === '0') r.classList.add('reply-row');
        });
        tbody.querySelectorAll('.thread-indent').forEach(el => {
            el.style.width = (parseFloat(el.closest('tr').dataset.depth) * 1.25) + 'em';
        });
        tbody.querySelectorAll('.thread-expand').forEach(el => {
            el.style.display = '';
            el.setAttribute('aria-expanded', 'false');
        });
        tbody.querySelectorAll('[data-reply-count]').forEach(el => { el.style.display = ''; });
    }

    applyFilter(document.getElementById('archive-filter').value);
}

function toggleThread(btn) {
    const row = btn.closest('tr');
    const root = row.dataset.threadRoot;
    const expanded = btn.getAttribute('aria-expanded') === 'true';
    document.querySelectorAll('#archive-tbody tr.reply-row[data-thread-root="' + CSS.escape(root) + '"]').forEach(r => {
        r.classList.toggle('expanded', !expanded);
    });
    btn.setAttribute('aria-expanded', String(!expanded));
}

function filterArchive(value) {
    applyFilter(value);
}

function applyFilter(value) {
    const needle = value.trim().toLowerCase();
    const tbody = getTbody();

    if (flatMode) {
        Array.from(tbody.rows).forEach(r => {
            const match = needle === '' || r.dataset.subject.includes(needle) || r.dataset.sender.includes(needle);
            r.style.display = match ? '' : 'none';
        });
        return;
    }

    if (needle === '') {
        Array.from(tbody.rows).forEach(r => {
            r.style.display = '';
            if (r.classList.contains('reply-row')) r.classList.remove('expanded');
        });
        tbody.querySelectorAll('.thread-expand').forEach(btn => {
            btn.setAttribute('aria-expanded', 'false');
        });
        return;
    }

    const byRoot = {};
    Array.from(tbody.rows).forEach(r => {
        (byRoot[r.dataset.threadRoot] ||= []).push(r);
    });

    Object.values(byRoot).forEach(rows => {
        const anyMatch = rows.some(r => r.dataset.subject.includes(needle) || r.dataset.sender.includes(needle));
        rows.forEach(r => {
            r.style.display = anyMatch ? '' : 'none';
            if (anyMatch && r.classList.contains('reply-row')) r.classList.add('expanded');
        });
        if (anyMatch) {
            const startRow = rows.find(r => r.dataset.isThreadStart === '1');
            const btn = startRow ? startRow.querySelector('.thread-expand') : null;
            if (btn) {
                btn.setAttribute('aria-expanded', 'true');
            }
        }
    });
}
