import React, { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { authApi, vaultApi, fetchCsrfToken, setCsrfToken } from './api';

const Lock = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
  </svg>
);
Lock.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Unlock = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
    <path d="M7 11V7a5 5 0 0 1 9.9-1"></path>
  </svg>
);
Unlock.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Key = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>
  </svg>
);
Key.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Plus = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <line x1="12" y1="5" x2="12" y2="19"></line>
    <line x1="5" y1="12" x2="19" y2="12"></line>
  </svg>
);
Plus.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Search = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <circle cx="11" cy="11" r="8"></circle>
    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
  </svg>
);
Search.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Eye = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
    <circle cx="12" cy="12" r="3"></circle>
  </svg>
);
Eye.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const EyeOff = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
    <line x1="1" y1="1" x2="23" y2="23"></line>
  </svg>
);
EyeOff.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Copy = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
  </svg>
);
Copy.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Trash = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <polyline points="3 6 5 6 21 6"></polyline>
    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
  </svg>
);
Trash.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Edit = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
  </svg>
);
Edit.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const X = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <line x1="18" y1="6" x2="6" y2="18"></line>
    <line x1="6" y1="6" x2="18" y2="18"></line>
  </svg>
);
X.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Shield = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
  </svg>
);
Shield.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const LogOut = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
    <polyline points="16 17 21 12 16 7"></polyline>
    <line x1="21" y1="12" x2="9" y2="12"></line>
  </svg>
);
LogOut.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const RefreshCw = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <polyline points="23 4 23 10 17 10"></polyline>
    <polyline points="1 20 1 14 7 14"></polyline>
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
  </svg>
);
RefreshCw.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Folder = ({ size = 24, className }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
  </svg>
);
Folder.propTypes = {
  size: PropTypes.number,
  className: PropTypes.string,
};

const Icons = {
  Lock,
  Unlock,
  Key,
  Plus,
  Search,
  Eye,
  EyeOff,
  Copy,
  Trash,
  Edit,
  X,
  Shield,
  LogOut,
  RefreshCw,
  Folder,
};

function Toast({ message, type, onClose }) {
  useEffect(() => {
    const timer = setTimeout(onClose, 3000);
    return () => clearTimeout(timer);
  }, [onClose]);

  return (
    <div className={`toast ${type}`}>
      <span>{message}</span>
    </div>
  );
}
Toast.propTypes = {
  message: PropTypes.string.isRequired,
  type: PropTypes.string,
  onClose: PropTypes.func.isRequired,
};

function AuthScreen({ onAuth, isInitialized }) {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const isRegister = !isInitialized;

  const requirements = [
    { text: 'At least 12 characters', met: password.length >= 12 },
    { text: 'Contains uppercase letter', met: /[A-Z]/.test(password) },
    { text: 'Contains lowercase letter', met: /[a-z]/.test(password) },
    { text: 'Contains number', met: /\d/.test(password) },
    { text: 'Contains special character', met: /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(password) },
  ];

  const passwordValid = requirements.every(r => r.met);
  const canSubmit = isRegister
    ? passwordValid && password === confirmPassword && password.length > 0
    : password.length > 0;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!canSubmit) return;

    setLoading(true);
    setError('');

    try {
      if (isRegister) {
        const result = await authApi.register(password);
        if (result.csrfToken) {
          setCsrfToken(result.csrfToken);
        }
        await new Promise(resolve => setTimeout(resolve, 300));
        onAuth();
      } else {
        const result = await authApi.login(password);
        if (result.csrfToken) {
          setCsrfToken(result.csrfToken);
        }
        await new Promise(resolve => setTimeout(resolve, 300));
        onAuth();
      }
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-screen">
      <div className="auth-container">
        <div className="auth-header">
          <div className="logo">
            <Icons.Shield className="logo-icon" />
            <span className="logo-text">SecureVault</span>
          </div>
          <h1>{isRegister ? 'Create Your Vault' : 'Unlock Vault'}</h1>
          <p>
            {isRegister
              ? 'Set a strong master password to protect your credentials'
              : 'Enter your master password to access your vault'}
          </p>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          {error && <div className="message error">{error}</div>}

          <div className="form-group">
            <label htmlFor="password">Master Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter master password"
              autoComplete="off"
              autoFocus
            />
          </div>

          {isRegister && (
            <>
              <div className="form-group">
                <label htmlFor="confirmPassword">Confirm Password</label>
                <input
                  id="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm master password"
                  autoComplete="off"
                />
              </div>

              <div className="password-requirements">
                <h4>Password Requirements</h4>
                <ul>
                  {requirements.map((req) => (
                    <li key={req.text} className={req.met ? 'met' : ''}>
                      <span className="icon">{req.met ? '✓' : '○'}</span>
                      {req.text}
                    </li>
                  ))}
                  <li className={password === confirmPassword && password.length > 0 ? 'met' : ''}>
                    <span className="icon">{password === confirmPassword && password.length > 0 ? '✓' : '○'}</span>
                    Passwords match
                  </li>
                </ul>
              </div>
            </>
          )}

          <button
            type="submit"
            className="btn btn-primary"
            disabled={!canSubmit || loading}
          >
            {loading ? (
              <span className="spinner"></span>
            ) : (
              <>
                {isRegister ? <Icons.Lock /> : <Icons.Unlock />}
                {isRegister ? 'Create Vault' : 'Unlock Vault'}
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
AuthScreen.propTypes = {
  onAuth: PropTypes.func.isRequired,
  isInitialized: PropTypes.bool.isRequired,
};

function CredentialModal({ credential, onSave, onClose, onAuthError }) {
  const isEdit = !!credential;
  const [formData, setFormData] = useState({
    title: credential?.title || '',
    username: credential?.username || '',
    password: credential?.password || '',
    url: credential?.url || '',
    category: credential?.category || 'General',
    notes: credential?.notes || '',
  });
  const [showPassword, setShowPassword] = useState(!isEdit);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setError('');
  }, [credential]);

  const handleChange = (field) => (e) => {
    setFormData(prev => ({ ...prev, [field]: e.target.value }));
  };

  const handleGeneratePassword = async () => {
    setError('');
    try {
      await fetchCsrfToken();
      const result = await vaultApi.generatePassword({ length: 20 });
      if (result && result.data && result.data.password) {
        setFormData(prev => ({ ...prev, password: result.data.password }));
        setShowPassword(true);
      } else {
        setError('Failed to generate password: invalid response');
      }
    } catch (err) {
      console.error('Password generation error:', err.status, err.message, err);
      if (err.status === 401 || err.status === 403) {
        setError('Session expired. Please refresh the page and log in again.');
      } else {
        setError('Unable to generate password. Please enter password manually.');
      }
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.title || !formData.username || !formData.password) {
      setError('Title, username, and password are required');
      return;
    }

    setLoading(true);
    setError('');

    try {
      if (isEdit) {
        await vaultApi.update(credential.id, formData);
      } else {
        await vaultApi.add(formData);
      }
      onSave();
    } catch (err) {
      if (err.status === 401 || err.status === 403) {
        try {
          await fetchCsrfToken();
          await new Promise(resolve => setTimeout(resolve, 300));
          if (isEdit) {
            await vaultApi.update(credential.id, formData);
          } else {
            await vaultApi.add(formData);
          }
          onSave();
        } catch (retryErr) {
          setError('Session expired. Please save your data and refresh the page to log in again.');
        }
      } else {
        setError(err.message || 'Failed to save credential');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{isEdit ? 'Edit Credential' : 'Add Credential'}</h2>
          <button className="modal-close" onClick={onClose}>
            <Icons.X />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {error && <div className="modal-error">{error}</div>}
          <div className="modal-body">

            <div className="form-group">
              <label>Title</label>
              <input
                type="text"
                value={formData.title}
                onChange={handleChange('title')}
                placeholder="e.g., Gmail Account"
                autoFocus
              />
            </div>

            <div className="form-group">
              <label>Username / Email</label>
              <input
                type="text"
                value={formData.username}
                onChange={handleChange('username')}
                placeholder="e.g., user@example.com"
                autoComplete="off"
              />
            </div>

            <div className="form-group">
              <label>Password</label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={formData.password}
                  onChange={handleChange('password')}
                  placeholder="Enter password"
                  autoComplete="off"
                  style={{ flex: 1 }}
                />
                <button
                  type="button"
                  className="btn btn-secondary btn-small"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{ width: 'auto', padding: '0 12px' }}
                >
                  {showPassword ? <Icons.EyeOff /> : <Icons.Eye />}
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-small"
                  onClick={handleGeneratePassword}
                  style={{ width: 'auto', padding: '0 12px' }}
                >
                  <Icons.RefreshCw />
                </button>
              </div>
            </div>

            <div className="form-group">
              <label>URL</label>
              <input
                type="text"
                value={formData.url}
                onChange={handleChange('url')}
                placeholder="e.g., https://gmail.com"
              />
            </div>

            <div className="form-group">
              <label>Category</label>
              <input
                type="text"
                value={formData.category}
                onChange={handleChange('category')}
                placeholder="e.g., Social, Work, Finance"
              />
            </div>

            <div className="form-group">
              <label>Notes</label>
              <textarea
                className="form-textarea"
                value={formData.notes}
                onChange={handleChange('notes')}
                placeholder="Additional notes..."
                rows={3}
              />
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? <span className="spinner"></span> : (isEdit ? 'Save Changes' : 'Add Credential')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
CredentialModal.propTypes = {
  credential: PropTypes.shape({
    id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    title: PropTypes.string,
    username: PropTypes.string,
    password: PropTypes.string,
    url: PropTypes.string,
    category: PropTypes.string,
    notes: PropTypes.string,
  }),
  onSave: PropTypes.func.isRequired,
  onClose: PropTypes.func.isRequired,
  onAuthError: PropTypes.func,
};

function ViewCredentialModal({ credential, onClose, onEdit, onDelete, showToast, onAuthError }) {
  const [showPassword, setShowPassword] = useState(false);
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [countdown, setCountdown] = useState(0);

  const handleShowPassword = async () => {
    if (showPassword) {
      setShowPassword(false);
      setPassword('');
      setCountdown(0);
      return;
    }

    setLoading(true);
    try {
      const result = await vaultApi.get(credential.id);
      setPassword(result.data.password);
      setShowPassword(true);
      setCountdown(5);
    } catch (err) {
      if (err.status === 401 && onAuthError) {
        onAuthError();
        return;
      }
      showToast('Failed to fetch password', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => {
        setCountdown(countdown - 1);
      }, 1000);
      return () => clearTimeout(timer);
    } else if (countdown === 0 && showPassword) {
      setShowPassword(false);
      setPassword('');
    }
  }, [countdown, showPassword]);

  const handleCopyPassword = async () => {
    try {
      let passwordToCopy = password;
      if (!passwordToCopy) {
        const result = await vaultApi.get(credential.id);
        passwordToCopy = result.data.password;
      }

      await navigator.clipboard.writeText(passwordToCopy);
      showToast('Password copied! Clipboard will clear in 30s', 'success');

      setTimeout(() => {
        navigator.clipboard.writeText('').catch(() => {});
      }, 30000);
    } catch (err) {
      if (err.status === 401 && onAuthError) {
        onAuthError();
        return;
      }
      showToast('Failed to copy password', 'error');
    }
  };

  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete this credential?')) {
      return;
    }

    try {
      await vaultApi.delete(credential.id);
      showToast('Credential deleted', 'success');
      onDelete();
    } catch (err) {
      if (err.status === 401 && onAuthError) {
        onAuthError();
        return;
      }
      showToast('Failed to delete credential', 'error');
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{credential.title}</h2>
          <button className="modal-close" onClick={onClose}>
            <Icons.X />
          </button>
        </div>

        <div className="modal-body">
          {credential.url && (
            <div className="view-field">
              <label>URL</label>
              <div className="view-field-value">
                <a
                  href={credential.url.startsWith('http') ? credential.url : `https://${credential.url}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: 'var(--accent-primary)' }}
                >
                  {credential.url}
                </a>
              </div>
            </div>
          )}

          <div className="view-field">
            <label>Username</label>
            <div className="view-field-value">{credential.username}</div>
          </div>

          <div className="view-field">
            <label>Password</label>
            <div className="password-field">
              <span className={`password-value ${!showPassword ? 'password-hidden' : ''}`}>
                {showPassword ? password : '••••••••••••'}
              </span>
              {showPassword && countdown > 0 && (
                <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                  Hiding in {countdown}s
                </span>
              )}
              <div className="password-actions">
                <button
                  className="action-btn"
                  onClick={handleShowPassword}
                  title={showPassword ? 'Hide password' : 'Show password'}
                >
                  {loading ? <span className="spinner"></span> : (showPassword ? <Icons.EyeOff /> : <Icons.Eye />)}
                </button>
                <button
                  className="action-btn"
                  onClick={handleCopyPassword}
                  title="Copy password"
                >
                  <Icons.Copy />
                </button>
              </div>
            </div>
          </div>

          {credential.category && (
            <div className="view-field">
              <label>Category</label>
              <div className="view-field-value">
                <span className="credential-category">{credential.category}</span>
              </div>
            </div>
          )}

          {credential.notes && (
            <div className="view-field">
              <label>Notes</label>
              <div className="view-field-value" style={{ whiteSpace: 'pre-wrap' }}>
                {credential.notes}
              </div>
            </div>
          )}

          <div className="view-field">
            <label>Last Updated</label>
            <div className="view-field-value" style={{ color: 'var(--text-muted)' }}>
              {new Date(credential.updatedAt).toLocaleString()}
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-danger btn-small" onClick={handleDelete}>
            <Icons.Trash /> Delete
          </button>
          <button className="btn btn-primary" onClick={onEdit}>
            <Icons.Edit /> Edit
          </button>
        </div>
      </div>
    </div>
  );
}
ViewCredentialModal.propTypes = {
  credential: PropTypes.shape({
    id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
    title: PropTypes.string.isRequired,
    username: PropTypes.string.isRequired,
    url: PropTypes.string,
    category: PropTypes.string,
    notes: PropTypes.string,
    updatedAt: PropTypes.oneOfType([PropTypes.string, PropTypes.instanceOf(Date)]).isRequired,
  }).isRequired,
  onClose: PropTypes.func.isRequired,
  onEdit: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
  showToast: PropTypes.func.isRequired,
  onAuthError: PropTypes.func,
};

function Dashboard({ onLogout }) {
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedCredential, setSelectedCredential] = useState(null);
  const [editCredential, setEditCredential] = useState(null);
  const [toasts, setToasts] = useState([]);
  const isInitialLoadRef = React.useRef(true);

  const showToast = useCallback((message, type = 'success') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const loadCredentials = useCallback(async (retryCount = 0) => {
    try {
      const result = await vaultApi.list();
      setCredentials(Array.isArray(result.data) ? result.data : []);
      isInitialLoadRef.current = false;
      setLoading(false);
    } catch (err) {
      if (err.status === 401 || err.status === 403) {
        setCredentials([]);
        if (isInitialLoadRef.current && retryCount < 5) {
          setTimeout(() => {
            loadCredentials(retryCount + 1);
          }, 300 * (retryCount + 1));
        } else if (!isInitialLoadRef.current) {
          onLogout();
        } else {
          isInitialLoadRef.current = false;
          setLoading(false);
        }
      } else {
        showToast('Failed to load credentials', 'error');
        setLoading(false);
      }
    }
  }, [showToast, onLogout]);

  useEffect(() => {
    const timer = setTimeout(() => {
      loadCredentials();
    }, 800);
    return () => clearTimeout(timer);
  }, [loadCredentials]);

  const handleLogout = async () => {
    try {
      await authApi.logout();
      onLogout();
    } catch (err) {
      showToast('Failed to logout', 'error');
    }
  };

  const handleSaveCredential = () => {
    setShowAddModal(false);
    setEditCredential(null);
    setSelectedCredential(null);
    loadCredentials();
    showToast(editCredential ? 'Credential updated' : 'Credential added', 'success');
  };

  const handleDeleteCredential = () => {
    setSelectedCredential(null);
    loadCredentials();
  };

  const filteredCredentials = credentials.filter(cred => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      cred.title.toLowerCase().includes(query) ||
      cred.username.toLowerCase().includes(query) ||
      (cred.url && cred.url.toLowerCase().includes(query)) ||
      (cred.category && cred.category.toLowerCase().includes(query))
    );
  });

  const getInitial = (title) => {
    return title ? title.charAt(0).toUpperCase() : '?';
  };

  return (
    <div className="dashboard">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <Icons.Shield />
            <span>SecureVault</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <button className="nav-item active">
            <Icons.Key />
            <span>All Passwords</span>
            <span className="count">{credentials.length}</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <button className="nav-item danger" onClick={handleLogout}>
            <Icons.LogOut />
            <span>Lock Vault</span>
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="main-header">
          <div className="search-box">
            <Icons.Search />
            <input
              type="text"
              placeholder="Search credentials..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <button className="btn btn-primary btn-small" onClick={() => setShowAddModal(true)}>
            <Icons.Plus /> Add New
          </button>
        </header>

        <div className="credentials-container">
          <div className="credentials-header">
            <h2>Your Credentials</h2>
          </div>

          {loading ? (
            <div className="empty-state">
              <div className="spinner" style={{ width: 40, height: 40 }}></div>
              <p>Loading credentials...</p>
            </div>
          ) : filteredCredentials.length === 0 ? (
            <div className="empty-state">
              <Icons.Key size={64} />
              <h3>{searchQuery ? 'No results found' : 'No credentials yet'}</h3>
              <p>
                {searchQuery
                  ? 'Try a different search term'
                  : 'Add your first credential to get started'}
              </p>
            </div>
          ) : (
            <div className="credentials-list">
              {filteredCredentials.map((cred) => (
                <div
                  key={cred.id}
                  className="credential-card"
                  onClick={() => setSelectedCredential(cred)}
                >
                  <div className="credential-icon">{getInitial(cred.title)}</div>
                  <div className="credential-info">
                    <div className="credential-title">{cred.title}</div>
                    <div className="credential-username">{cred.username}</div>
                  </div>
                  {cred.category && (
                    <span className="credential-category">{cred.category}</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </main>

      {/* Modals */}
      {showAddModal && (
        <CredentialModal
          onSave={handleSaveCredential}
          onClose={() => setShowAddModal(false)}
          onAuthError={onLogout}
        />
      )}

      {editCredential && (
        <CredentialModal
          credential={editCredential}
          onSave={handleSaveCredential}
          onClose={() => setEditCredential(null)}
          onAuthError={onLogout}
        />
      )}

      {selectedCredential && !editCredential && (
        <ViewCredentialModal
          credential={selectedCredential}
          onClose={() => setSelectedCredential(null)}
          onEdit={() => {
            setEditCredential(selectedCredential);
          }}
          onDelete={handleDeleteCredential}
          showToast={showToast}
          onAuthError={onLogout}
        />
      )}

      {/* Toast notifications */}
      <div className="toast-container">
        {toasts.map(toast => (
          <Toast
            key={toast.id}
            message={toast.message}
            type={toast.type}
            onClose={() => removeToast(toast.id)}
          />
        ))}
      </div>
    </div>
  );
}
Dashboard.propTypes = {
  onLogout: PropTypes.func.isRequired,
};

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function checkStatus() {
      try {
        await fetchCsrfToken();
        const status = await authApi.getStatus();
        setIsInitialized(status.initialized);
        setIsAuthenticated(status.authenticated);
        if (status.csrfToken) {
          setCsrfToken(status.csrfToken);
        }
      } catch (err) {
        console.error('Failed to check status:', err);
      } finally {
        setLoading(false);
      }
    }
    checkStatus();
  }, []);

  const handleAuth = useCallback(() => {
    setIsAuthenticated(true);
    setIsInitialized(true);
  }, []);

  const handleLogout = () => {
    setIsAuthenticated(false);
  };

  if (loading) {
    return (
      <div className="auth-screen">
        <div style={{ textAlign: 'center' }}>
          <div className="spinner" style={{ width: 40, height: 40, margin: '0 auto' }}></div>
          <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      {isAuthenticated ? (
        <Dashboard onLogout={handleLogout} />
      ) : (
        <AuthScreen onAuth={handleAuth} isInitialized={isInitialized} />
      )}
    </div>
  );
}

export default App;

