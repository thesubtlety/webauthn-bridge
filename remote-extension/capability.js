// Runs in a real, top-level chrome-extension:// document on REMOTE Chrome.
// It never calls credentials.get(), so it never asks the user to sign in.
(async () => {
  const nonce = new URL(location.href).searchParams.get('nonce');
  if (!nonce || !/^[0-9a-f-]{36}$/.test(nonce)) return;
  let available = false, source = 'browser-api', error = null;
  try {
    if (!isSecureContext || typeof PublicKeyCredential === 'undefined' || typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
      source = 'api-unavailable';
      error = 'isUserVerifyingPlatformAuthenticatorAvailable is unavailable in this document';
    } else {
      available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable() === true;
    }
  } catch (e) {
    source = 'api-error';
    error = `${e?.name || 'Error'}: ${String(e?.message || e).slice(0,120)}`;
  }
  await chrome.runtime.sendMessage({action: 'capabilityProbeResult', nonce, available, source, error}).catch(() => {});
})();
