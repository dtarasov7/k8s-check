RUNTIME_SERVICE_UNITS = (
    "containerd.service",
    "containerd-deckhouse.service",
    "crio.service",
)

ACTIVE_SERVICE_STATES = ("active", "activating")


def loaded_runtime_service_states(service_states):
    result = {}
    for unit in RUNTIME_SERVICE_UNITS:
        state = service_states.get(unit, {})
        if state.get("status") != "collected":
            continue
        load_state = state.get("properties", {}).get("LoadState")
        if load_state != "loaded":
            continue
        result[unit] = state
    return result


def runtime_service_is_active(state):
    return state.get("properties", {}).get("ActiveState") in ACTIVE_SERVICE_STATES
