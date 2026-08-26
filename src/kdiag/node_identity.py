def _normalized_names(values):
    result = set()
    for value in values:
        text = str(value or "").strip().rstrip(".").lower()
        if text:
            result.add(text)
    return result


def _short_names(values):
    return {value.split(".", 1)[0] for value in values}


def match_node_identities(node_snapshots, kubernetes_nodes):
    """Return unambiguous inventory alias -> Kubernetes Node name matches."""
    inventory = {}
    for alias, snapshot in node_snapshots.items():
        host = snapshot.get("host", {}) or {}
        full = _normalized_names((alias, host.get("hostname"), host.get("fqdn")))
        inventory[alias] = (full, _short_names(full))

    kubernetes = {}
    for item in kubernetes_nodes:
        metadata = item.get("metadata", {}) or {}
        name = metadata.get("name")
        if not name:
            continue
        labels = metadata.get("labels", {}) or {}
        full = _normalized_names((name, labels.get("kubernetes.io/hostname")))
        kubernetes[name] = (full, _short_names(full))

    candidates = {}
    for alias, (inventory_full, inventory_short) in inventory.items():
        scored = []
        for name, (kubernetes_full, kubernetes_short) in kubernetes.items():
            if inventory_full & kubernetes_full:
                scored.append((2, name))
            elif inventory_short & kubernetes_short:
                scored.append((1, name))
        if scored:
            best_score = max(score for score, _name in scored)
            candidates[alias] = {name for score, name in scored if score == best_score}

    reverse = {}
    for alias, names in candidates.items():
        if len(names) == 1:
            reverse.setdefault(next(iter(names)), set()).add(alias)

    return {
        alias: next(iter(names))
        for alias, names in candidates.items()
        if len(names) == 1 and len(reverse.get(next(iter(names)), ())) == 1
    }
