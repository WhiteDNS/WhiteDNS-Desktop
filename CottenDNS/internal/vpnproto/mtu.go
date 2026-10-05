package vpnproto

// MinMTUDownloadProbePayload is the minimum requested response payload accepted
// by native and legacy MTU download probes. Client search boundaries must meet
// this wire minimum even when the configured data MTU is smaller.
const MinMTUDownloadProbePayload = 30
