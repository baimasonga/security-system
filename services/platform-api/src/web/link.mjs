import { api, content, form, node, panel, signIn, wireReport } from './public.mjs';

// Unlock page for password-protected or sign-in public short links. Before leaving, the visitor sees where the link
// goes, so a link cannot silently send them somewhere unexpected.
const code = location.pathname.split('/').pop();

function leaving(location) {
  const host = new URL(location).host;
  content().replaceChildren(
    panel(
      node('h1', 'You are leaving Rokela'),
      node('p', `This link goes to ${host}.`),
      (() => {
        const a = node('a', `Continue to ${host}`, 'primary-link');
        a.href = location;
        a.rel = 'noopener noreferrer';
        return a;
      })(),
    ),
  );
}

async function unlock(password) {
  try {
    const r = await api(
      `/v1/public/short-links/${encodeURIComponent(code)}/unlock`,
      'POST',
      password ? { password } : {},
    );
    leaving(r.location);
  } catch (e) {
    if (e.code === 'unauthenticated')
      return content().replaceChildren(signIn(() => unlock(password)));
    if (e.code === 'password_required')
      return ask(password ? 'That password was not correct.' : undefined);
    content().replaceChildren(panel(node('h1', 'Link unavailable'), node('p', e.message)));
  }
}

function ask(error) {
  content().replaceChildren(
    panel(
      node('h1', 'Protected link'),
      node('p', error || 'Enter the password you were given to continue.'),
      form(
        [
          {
            name: 'password',
            label: 'Password',
            type: 'password',
            autocomplete: 'current-password',
          },
        ],
        'Continue',
        (v) => unlock(v.password),
      ),
    ),
  );
}

wireReport();
void unlock();
