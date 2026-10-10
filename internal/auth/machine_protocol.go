package auth

const MachineIdentityRevision = "machine-identity-v1"

// VMDMachineIdentityHeader attests that the local instance resolver implements
// durable machine ownership classification, including fail-closed unknown rows.
const VMDMachineIdentityHeader = "X-Superserve-Machine-Identity"

// ProxyMachineIdentityHeader proves the requesting proxy understands machine ownership.
const ProxyMachineIdentityHeader = "X-Superserve-Proxy-Machine-Identity"
