# Approved Warrior console design

The user approved the desktop/mobile concept before implementation. The portal
adopts its compact cloud-console composition: white full-width utility header,
neutral gray workspace, orange navigation and primary actions, a bounded sidebar,
crisp bordered panels and tables, compact desktop forms and stacked mobile records.
The existing Warrior icon/name and Quantix ownership remain; no Cloudflare logo,
identity-provider claim or hosting claim is introduced.

The orange primary action is deliberately darker than the decorative orange
navigation rule so white action text remains readable. Success, warning, failure
and unknown states retain distinct colors and their text labels; inventory state
is not monitoring health. Credential dialogs and error notices use the same visual
system, without changing their authorization or data lifecycle.

On narrow screens the Menu button exposes the existing navigation. Its expanded
state is announced, hidden links cannot receive focus, Escape closes it and restores
focus to Menu, and choosing a view closes the menu and focuses the main content.
Resizing resets the menu, and signing out removes the authenticated navigation and
workspace controls. Touch targets remain at least 44 pixels on mobile. Desktop
navigation remains immediately available. Forms keep DOM reading order when their
wide-screen columns stack; tables retain explicit mobile field labels. No animation
is required, and reduced-motion support remains in place.

The change adds no session persistence, server endpoint, commercial permission,
external font/script dependency or hosting dependency. Existing CSP and all backend
controls remain authoritative. The static HTML/CSS and portal navigation module are
served by the existing asset allowlist. Rollback is a source/UI release rollback;
no database migration or secret replacement is required.

Browser evidence uses isolated synthetic accounts. Generated concepts and local
screenshots are not production data or proof of production rollout. Verify the
served HTML, portal.css and portal.mjs against the released commit after deployment,
then complete a controlled sign-in and mobile-navigation smoke test.
