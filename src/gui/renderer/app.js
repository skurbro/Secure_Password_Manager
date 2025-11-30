let credentials = [];
let currentCredentialId = null;
let passwordRevealTimeout = null;
let actualPassword = '';

const screens = {
  loading: document.getElementById('loading-screen'),
  setup: document.getElementById('setup-screen'),
  login: document.getElementById('login-screen'),
  vault: document.getElementById('vault-screen'),
};

const modals = {
  credential: document.getElementById('credential-modal'),
  view: document.getElementById('view-modal'),
  generator: document.getElementById('generator-modal'),
};

async function init() {
  try {
    const isInit = await window.api.vault.isInitialized();
    const isUnlocked = await window.api.vault.isUnlocked();

    if (!isInit) {
      showScreen('setup');
    } else if (isUnlocked) {
      showScreen('vault');
      await loadCredentials();
    } else {
      showScreen('login');
    }

    setupEventListeners();

    window.api.vault.onLocked(() => {
      showScreen('login');
      showToast('Vault locked due to inactivity', 'info');
    });

    document.addEventListener('click', () => window.api.activity.ping());
    document.addEventListener('keydown', () => window.api.activity.ping());

  } catch (error) {
    console.error('Initialization error:', error);
    showToast('Failed to initialize application', 'error');
  }
}

function showScreen(screenName) {
  Object.values(screens).forEach(screen => screen.classList.remove('active'));
  if (screens[screenName]) {
    screens[screenName].classList.add('active');
  }
}

function setupEventListeners() {
  document.getElementById('setup-form').addEventListener('submit', handleSetup);
  document.getElementById('setup-password').addEventListener('input', handlePasswordInput);

  document.getElementById('login-form').addEventListener('submit', handleLogin);

  document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const input = document.getElementById(targetId);
      input.type = input.type === 'password' ? 'text' : 'password';
    });
  });

  document.getElementById('add-credential-btn').addEventListener('click', () => openCredentialModal());
  document.getElementById('add-first-btn')?.addEventListener('click', () => openCredentialModal());
  document.getElementById('lock-btn').addEventListener('click', handleLock);
  document.getElementById('generate-password-btn').addEventListener('click', openGeneratorModal);

  document.getElementById('search-input').addEventListener('input', debounce(handleSearch, 300));

  document.querySelectorAll('[data-view]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-view]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });

  document.getElementById('credential-form').addEventListener('submit', handleCredentialSave);
  document.getElementById('modal-close').addEventListener('click', closeCredentialModal);
  document.getElementById('modal-cancel').addEventListener('click', closeCredentialModal);
  document.getElementById('generate-cred-password').addEventListener('click', async () => {
    const result = await window.api.password.generate(16);
    if (result.success) {
      document.getElementById('cred-password').value = result.data;
      document.getElementById('cred-password').type = 'text';
    }
  });
  modals.credential.querySelector('.modal-backdrop').addEventListener('click', closeCredentialModal);

  document.getElementById('view-modal-close').addEventListener('click', closeViewModal);
  document.getElementById('view-edit-btn').addEventListener('click', handleEditFromView);
  document.getElementById('view-delete-btn').addEventListener('click', handleDeleteFromView);
  document.getElementById('show-password-btn').addEventListener('click', handleShowPassword);
  modals.view.querySelector('.modal-backdrop').addEventListener('click', closeViewModal);

  document.querySelectorAll('.copy-btn[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => handleCopy(btn.dataset.copy));
  });

  document.getElementById('generator-close').addEventListener('click', closeGeneratorModal);
  document.getElementById('regenerate-btn').addEventListener('click', generatePassword);
  document.getElementById('copy-generated').addEventListener('click', copyGeneratedPassword);
  document.getElementById('password-length').addEventListener('input', updateLengthDisplay);
  modals.generator.querySelector('.modal-backdrop').addEventListener('click', closeGeneratorModal);

  ['include-upper', 'include-lower', 'include-numbers', 'include-symbols'].forEach(id => {
    document.getElementById(id).addEventListener('change', generatePassword);
  });
}

async function handleSetup(e) {
  e.preventDefault();

  const password = document.getElementById('setup-password').value;
  const confirm = document.getElementById('setup-confirm').value;
  const errorEl = document.getElementById('setup-error');
  const btn = document.getElementById('setup-btn');

  errorEl.classList.remove('visible');

  if (password !== confirm) {
    showError(errorEl, 'Passwords do not match');
    return;
  }

  btn.classList.add('loading');
  btn.disabled = true;

  try {
    const result = await window.api.vault.init(password);

    if (result.success) {
      showToast('Vault created successfully!', 'success');
      showScreen('vault');
      await loadCredentials();
    } else {
      showError(errorEl, result.message || 'Failed to create vault');
    }
  } catch (error) {
    showError(errorEl, 'An error occurred. Please try again.');
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

function handlePasswordInput(e) {
  const password = e.target.value;
  const strengthBar = document.querySelector('.strength-bar');
  const strengthText = document.querySelector('.strength-text');

  const requirements = {
    length: password.length >= 12,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    symbol: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password),
  };

  Object.entries(requirements).forEach(([key, met]) => {
    const el = document.getElementById(`req-${key}`);
    if (el) {
      el.classList.toggle('met', met);
    }
  });

  const metCount = Object.values(requirements).filter(Boolean).length;

  strengthBar.className = 'strength-bar';
  if (password.length === 0) {
    strengthText.textContent = 'Enter a password';
  } else if (metCount <= 2) {
    strengthBar.classList.add('weak');
    strengthText.textContent = 'Weak';
  } else if (metCount === 3) {
    strengthBar.classList.add('fair');
    strengthText.textContent = 'Fair';
  } else if (metCount === 4) {
    strengthBar.classList.add('good');
    strengthText.textContent = 'Good';
  } else {
    strengthBar.classList.add('strong');
    strengthText.textContent = 'Strong';
  }
}

async function handleLogin(e) {
  e.preventDefault();

  const password = document.getElementById('login-password').value;
  const errorEl = document.getElementById('login-error');
  const btn = document.getElementById('login-btn');

  errorEl.classList.remove('visible');
  btn.classList.add('loading');
  btn.disabled = true;

  try {
    const result = await window.api.vault.unlock(password);

    if (result.success) {
      showToast('Vault unlocked', 'success');
      document.getElementById('login-password').value = '';
      showScreen('vault');
      await loadCredentials();
    } else {
      showError(errorEl, result.message || 'Invalid password');
    }
  } catch (error) {
    showError(errorEl, 'An error occurred. Please try again.');
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

async function handleLock() {
  await window.api.vault.lock();
  showScreen('login');
  showToast('Vault locked', 'info');
}

async function loadCredentials() {
  try {
    const result = await window.api.credentials.list();

    if (result.success) {
      credentials = result.data || [];
      renderCredentials();
      updateCredentialCount();
      await loadCategories();
    }
  } catch (error) {
    console.error('Failed to load credentials:', error);
    showToast('Failed to load credentials', 'error');
  }
}

function renderCredentials(filteredCreds = null) {
  const list = document.getElementById('credentials-list');
  const emptyState = document.getElementById('empty-state');
  const credsToRender = filteredCreds || credentials;

  if (credsToRender.length === 0) {
    list.innerHTML = '';
    emptyState.classList.remove('hidden');
    return;
  }

  emptyState.classList.add('hidden');

  list.innerHTML = credsToRender.map(cred => `
    <div class="credential-card" data-id="${cred.id}">
      <div class="credential-icon">${getInitials(cred.title)}</div>
      <div class="credential-info">
        <div class="credential-title">${escapeHtml(cred.title)}</div>
        <div class="credential-username">${escapeHtml(cred.username)}</div>
      </div>
      <span class="credential-category">${escapeHtml(cred.category || 'General')}</span>
    </div>
  `).join('');

  list.querySelectorAll('.credential-card').forEach(card => {
    card.addEventListener('click', () => openViewModal(card.dataset.id));
  });
}

function updateCredentialCount() {
  document.getElementById('all-count').textContent = credentials.length;
  document.getElementById('credential-count').textContent = `${credentials.length} item${credentials.length !== 1 ? 's' : ''}`;
}

async function loadCategories() {
  try {
    const result = await window.api.credentials.categories();

    if (result.success && result.data) {
      const container = document.getElementById('categories-list');
      container.innerHTML = result.data.map(cat => `
        <button class="nav-item" data-category="${escapeHtml(cat)}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
          </svg>
          <span>${escapeHtml(cat)}</span>
        </button>
      `).join('');

      const datalist = document.getElementById('category-suggestions');
      datalist.innerHTML = result.data.map(cat => `<option value="${escapeHtml(cat)}">`).join('');
    }
  } catch (error) {
    console.error('Failed to load categories:', error);
  }
}

async function handleSearch(e) {
  const query = e.target.value.trim();

  if (!query) {
    renderCredentials();
    return;
  }

  try {
    const result = await window.api.credentials.search(query);
    if (result.success) {
      renderCredentials(result.data);
    }
  } catch (error) {
    console.error('Search failed:', error);
  }
}

function openCredentialModal(credentialData = null) {
  const modal = modals.credential;
  const form = document.getElementById('credential-form');
  const title = document.getElementById('modal-title');

  form.reset();
  document.getElementById('credential-id').value = '';

  if (credentialData) {
    title.textContent = 'Edit Credential';
    document.getElementById('credential-id').value = credentialData.id;
    document.getElementById('cred-title').value = credentialData.title;
    document.getElementById('cred-url').value = credentialData.url || '';
    document.getElementById('cred-username').value = credentialData.username;
    document.getElementById('cred-password').value = credentialData.password || '';
    document.getElementById('cred-category').value = credentialData.category || '';
    document.getElementById('cred-notes').value = credentialData.notes || '';
  } else {
    title.textContent = 'Add Credential';
  }

  modal.classList.add('active');
}

function closeCredentialModal() {
  modals.credential.classList.remove('active');
}

async function handleCredentialSave(e) {
  e.preventDefault();

  const id = document.getElementById('credential-id').value;
  const data = {
    title: document.getElementById('cred-title').value,
    url: document.getElementById('cred-url').value,
    username: document.getElementById('cred-username').value,
    password: document.getElementById('cred-password').value,
    category: document.getElementById('cred-category').value || 'General',
    notes: document.getElementById('cred-notes').value,
  };

  const btn = document.getElementById('modal-save');
  btn.classList.add('loading');
  btn.disabled = true;

  try {
    let result;
    if (id) {
      result = await window.api.credentials.update(id, data);
    } else {
      result = await window.api.credentials.add(data);
    }

    if (result.success) {
      showToast(id ? 'Credential updated' : 'Credential added', 'success');
      closeCredentialModal();
      await loadCredentials();
    } else {
      showToast(result.message || 'Failed to save', 'error');
    }
  } catch (error) {
    showToast('An error occurred', 'error');
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

async function openViewModal(id) {
  try {
    const result = await window.api.credentials.get(id);

    if (!result.success || !result.data) {
      showToast('Credential not found', 'error');
      return;
    }

    const cred = result.data;
    currentCredentialId = id;
    actualPassword = cred.password;

    document.getElementById('view-modal-title').textContent = cred.title;
    document.getElementById('view-title-value').textContent = cred.title;
    document.getElementById('view-url-value').textContent = cred.url || '-';
    document.getElementById('view-username-value').textContent = cred.username;
    document.getElementById('view-password-value').textContent = '••••••••••••';
    document.getElementById('view-password-value').classList.add('password-hidden');
    document.getElementById('view-category-value').textContent = cred.category || 'General';
    document.getElementById('view-notes-value').textContent = cred.notes || '-';
    document.getElementById('view-created-value').textContent = formatDate(cred.createdAt);
    document.getElementById('view-updated-value').textContent = formatDate(cred.updatedAt);

    modals.view.classList.add('active');
  } catch (error) {
    console.error('Failed to load credential:', error);
    showToast('Failed to load credential', 'error');
  }
}

function closeViewModal() {
  modals.view.classList.remove('active');
  currentCredentialId = null;
  actualPassword = '';

  if (passwordRevealTimeout) {
    clearTimeout(passwordRevealTimeout);
    passwordRevealTimeout = null;
  }
}

function handleShowPassword() {
  const passwordEl = document.getElementById('view-password-value');
  const btn = document.getElementById('show-password-btn');

  passwordEl.textContent = actualPassword;
  passwordEl.classList.remove('password-hidden');
  btn.disabled = true;
  btn.querySelector('span').textContent = '5s...';

  let countdown = 5;
  const countdownInterval = setInterval(() => {
    countdown--;
    btn.querySelector('span').textContent = `${countdown}s...`;
  }, 1000);

  passwordRevealTimeout = setTimeout(() => {
    passwordEl.textContent = '••••••••••••';
    passwordEl.classList.add('password-hidden');
    btn.disabled = false;
    btn.querySelector('span').textContent = 'View (5s)';
    clearInterval(countdownInterval);
  }, 5000);
}

async function handleCopy(field) {
  let text;

  if (field === 'username') {
    text = document.getElementById('view-username-value').textContent;
  } else if (field === 'password') {
    text = actualPassword;
  }

  if (text) {
    const result = await window.api.clipboard.copy(text);
    if (result.success) {
      showToast(`${field === 'password' ? 'Password' : 'Username'} copied (clears in 30s)`, 'success');
    }
  }
}

async function handleEditFromView() {
  if (!currentCredentialId) return;

  const result = await window.api.credentials.get(currentCredentialId);
  if (result.success) {
    closeViewModal();
    openCredentialModal(result.data);
  }
}

async function handleDeleteFromView() {
  if (!currentCredentialId) return;

  if (!confirm('Are you sure you want to delete this credential?')) {
    return;
  }

  try {
    const result = await window.api.credentials.delete(currentCredentialId);

    if (result.success) {
      showToast('Credential deleted', 'success');
      closeViewModal();
      await loadCredentials();
    } else {
      showToast('Failed to delete', 'error');
    }
  } catch (error) {
    showToast('An error occurred', 'error');
  }
}

function openGeneratorModal() {
  modals.generator.classList.add('active');
  generatePassword();
}

function closeGeneratorModal() {
  modals.generator.classList.remove('active');
}

async function generatePassword() {
  const length = parseInt(document.getElementById('password-length').value, 10);
  const options = {
    includeUppercase: document.getElementById('include-upper').checked,
    includeLowercase: document.getElementById('include-lower').checked,
    includeNumbers: document.getElementById('include-numbers').checked,
    includeSymbols: document.getElementById('include-symbols').checked,
  };

  if (!Object.values(options).some(Boolean)) {
    document.getElementById('include-lower').checked = true;
    options.includeLowercase = true;
  }

  const result = await window.api.password.generate(length, options);
  if (result.success) {
    document.getElementById('generated-password').value = result.data;
  }
}

function updateLengthDisplay(e) {
  document.getElementById('length-value').textContent = e.target.value;
  generatePassword();
}

async function copyGeneratedPassword() {
  const password = document.getElementById('generated-password').value;
  const result = await window.api.clipboard.copy(password);
  if (result.success) {
    showToast('Password copied (clears in 30s)', 'success');
  }
}

function showError(element, message) {
  element.textContent = message;
  element.classList.add('visible');
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const iconPath = type === 'success'
    ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
    : '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>';

  toast.innerHTML = `
    <svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      ${iconPath}
    </svg>
    <span class="toast-message">${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function getInitials(text) {
  return text.substring(0, 2).toUpperCase();
}

function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function debounce(fn, delay) {
  let timeoutId;
  return function (...args) {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn.apply(this, args), delay);
  };
}

document.addEventListener('DOMContentLoaded', init);

