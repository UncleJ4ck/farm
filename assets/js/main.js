// Mobile nav toggle
const toggle = document.querySelector('.nav-toggle');
const navLinks = document.querySelector('.nav-links');

if (toggle && navLinks) {
  toggle.addEventListener('click', () => {
    const open = navLinks.classList.toggle('is-open');
    toggle.setAttribute('aria-expanded', String(open));
  });

  // Close on link click
  navLinks.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
      navLinks.classList.remove('is-open');
      toggle.setAttribute('aria-expanded', 'false');
    });
  });

  // Close on outside click
  document.addEventListener('click', e => {
    if (!e.target.closest('.site-nav')) {
      navLinks.classList.remove('is-open');
      toggle.setAttribute('aria-expanded', 'false');
    }
  });
}

// Copy code blocks on click
document.querySelectorAll('pre code').forEach(block => {
  const pre = block.parentElement;
  const btn = document.createElement('button');
  btn.textContent = 'copy';
  btn.className = 'copy-btn';
  btn.setAttribute('aria-label', 'Copy code');

  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(block.textContent);
      btn.textContent = 'copied';
      setTimeout(() => { btn.textContent = 'copy'; }, 1800);
    } catch {
      btn.textContent = 'error';
    }
  });

  pre.style.position = 'relative';
  pre.appendChild(btn);
});
