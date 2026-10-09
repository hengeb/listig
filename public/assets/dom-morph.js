// Minimal DOM morphing for self-refreshing page parts (list-manage.js): listigMorph(container,
// html) patches `container` to match `html` while keeping every node that is already right.
// Replacing the container's innerHTML instead would rebuild all nodes — losing the text
// selection, hover and focus, and letting the scroll position jump when the nodes the browser
// anchors the scroll to disappear. Elements with a `data-key` are matched by that key (so a new
// table row is inserted instead of every row after it being rewritten), everything else by
// position and node name. Attributes and text are only written when they differ.

function listigMorph(container, html) {
    const template = document.createElement('template');
    template.innerHTML = html;
    listigMorphChildren(container, template.content);
}

function listigMorphChildren(oldParent, newParent) {
    const keyOf = (node) => node.nodeType === Node.ELEMENT_NODE ? node.getAttribute('data-key') : null;
    const oldByKey = new Map();
    for (const node of oldParent.childNodes) {
        const key = keyOf(node);
        if (key !== null) {
            oldByKey.set(key, node);
        }
    }

    const kept = new Set();
    let ref = oldParent.firstChild; // the next old node that may still be matched by position
    for (const next of Array.from(newParent.childNodes)) {
        const key = keyOf(next);
        let match = null;
        if (key !== null) {
            match = oldByKey.get(key) ?? null;
        } else if (ref !== null && keyOf(ref) === null && ref.nodeType === next.nodeType && ref.nodeName === next.nodeName) {
            match = ref;
        }

        if (match !== null) {
            if (match !== ref) {
                oldParent.insertBefore(match, ref); // keep the order of the new tree
            }
            listigMorphNode(match, next);
            kept.add(match);
            ref = match.nextSibling;
        } else {
            oldParent.insertBefore(next, ref); // moves the node out of the new tree
            kept.add(next);
        }
    }

    for (const node of Array.from(oldParent.childNodes)) {
        if (!kept.has(node)) {
            oldParent.removeChild(node);
        }
    }
}

function listigMorphNode(oldNode, newNode) {
    if (oldNode.nodeType !== Node.ELEMENT_NODE) {
        if (oldNode.nodeValue !== newNode.nodeValue) {
            oldNode.nodeValue = newNode.nodeValue;
        }
        return;
    }
    for (const attr of Array.from(oldNode.attributes)) {
        if (!newNode.hasAttribute(attr.name)) {
            oldNode.removeAttribute(attr.name);
        }
    }
    for (const attr of Array.from(newNode.attributes)) {
        if (oldNode.getAttribute(attr.name) !== attr.value) {
            oldNode.setAttribute(attr.name, attr.value);
        }
    }
    listigMorphChildren(oldNode, newNode);
}
