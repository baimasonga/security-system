const status = document.getElementById('payment-status');
const open = document.getElementById('open-payment');
async function initialize() {
  const values = new URL(location.href).searchParams.getAll('_ptxn');
  if (values.length !== 1 || !/^txn_[a-z0-9]{26}$/.test(values[0]))
    throw new Error('This payment link is invalid. Return to your account to open the checkout.');
  const response = await fetch('/v1/billing/checkout-options');
  if (!response.ok)
    throw new Error('Payment is not configured. Contact support before proceeding.');
  const options = await response.json();
  if (options.portal_origin) {
    const portal = new URL(options.portal_origin);
    if (
      portal.protocol !== 'https:' ||
      portal.username ||
      portal.password ||
      portal.origin === location.origin
    )
      throw new Error('Payment origin is not isolated from the account portal.');
    document.getElementById('return-account').href = portal.origin;
  }
  if (!window.Paddle)
    throw new Error('Secure payment could not load. Check your connection and retry.');
  if (options.environment === 'sandbox') window.Paddle.Environment.set('sandbox');
  window.Paddle.Initialize({
    token: options.client_token,
    eventCallback: (event) => {
      if (event.name === 'checkout.completed')
        status.textContent =
          'Payment submitted. Return to your account; subscription confirmation arrives through the payment provider.';
    },
  });
  status.textContent =
    options.environment === 'sandbox'
      ? 'Sandbox checkout — no live payment.'
      : 'Secure payment is ready.';
  open.disabled = false;
  open.addEventListener('click', () => {
    try {
      window.Paddle.Checkout.open({ transactionId: values[0] });
    } catch {
      status.textContent = 'Payment could not open. Retry or contact support.';
    }
  });
}
initialize().catch((error) => {
  status.textContent = error.message;
});
