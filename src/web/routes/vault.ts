import { Router, Response } from 'express';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth';
import { vaultStorage } from '../../core/storage';
import { generatePassword } from '../../core/crypto';
import { logSecurityEvent, SecurityEvent, Outcome } from '../../core/logger';

const router = Router();

router.post('/generate-password', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (process.env.DEBUG_CSRF === '1' || process.env.DEBUG_AUTH === '1') {
      const clientToken = (req.headers['x-csrf-token'] || req.headers['X-CSRF-Token']) as string | undefined;
      const clientShort = clientToken ? `${clientToken.slice(0,8)}...${clientToken.slice(-8)}` : 'none';
      console.log(`[VAULT DEBUG] generate-password user=${req.userId} session=${req.sessionID} isAuth=${req.session?.isAuthenticated} clientToken=${clientShort}`);
    }
    const length = Math.min(Math.max(parseInt(req.body.length) || 16, 8), 128);

    const options = {
      includeUppercase: req.body.uppercase !== false,
      includeLowercase: req.body.lowercase !== false,
      includeNumbers: req.body.numbers !== false,
      includeSymbols: req.body.symbols !== false,
    };

    const password = generatePassword(length, options);

    logSecurityEvent({
      event: SecurityEvent.PASSWORD_GENERATED,
      userId: req.userId!,
      sessionId: req.sessionID,
      outcome: Outcome.SUCCESS,
      message: 'Password generated via web',
    });

    res.json({
      success: true,
      data: { password, length },
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to generate password',
      message: 'An unexpected error occurred',
    });
  }
});

router.use(requireAuth);

type FieldSchema = {
  name: string;
  required: boolean;
  maxLength: number;
  validator?: 'string' | 'url';
};

type ValidationResult = { valid: boolean; value: string; error?: string };

function sanitizeString(input: string): string {
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '');
}

function validateField(input: unknown, schema: FieldSchema): ValidationResult {
  const isEmpty = input === undefined || input === null || input === '';
  
  if (isEmpty) {
    if (schema.required) {
      return { valid: false, value: '', error: `${schema.name} is required` };
    }
    return { valid: true, value: '' };
  }

  if (typeof input !== 'string') {
    return { valid: false, value: '', error: `${schema.name} must be a string` };
  }

  const trimmed = input.trim().slice(0, schema.maxLength);
  
  if (schema.validator === 'string') {
    const cleaned = sanitizeString(trimmed);
    return { valid: true, value: cleaned };
  }
  
  return { valid: true, value: trimmed };
}

function validateFields(body: Record<string, unknown>, schema: Record<string, FieldSchema>): { valid: boolean; data: Record<string, string>; error?: string } {
  const result: Record<string, string> = {};
  
  for (const [field, fieldSchema] of Object.entries(schema)) {
    if (body[field] === undefined) {
      continue;
    }
    
    const validation = validateField(body[field], fieldSchema);
    if (!validation.valid) {
      return { valid: false, data: {}, error: validation.error };
    }
    result[field] = validation.value;
  }
  
  return { valid: true, data: result };
}

const CREDENTIAL_SCHEMA = {
  title: { name: 'Title', required: true, maxLength: 200, validator: 'string' as const },
  username: { name: 'Username', required: true, maxLength: 200, validator: 'string' as const },
  password: { name: 'Password', required: true, maxLength: 500, validator: 'string' as const },
  url: { name: 'URL', required: false, maxLength: 2000, validator: 'url' as const },
  category: { name: 'Category', required: false, maxLength: 50, validator: 'string' as const },
  notes: { name: 'Notes', required: false, maxLength: 2000, validator: 'string' as const },
};

const UPDATE_SCHEMA = {
  title: { name: 'Title', required: false, maxLength: 200, validator: 'string' as const },
  username: { name: 'Username', required: false, maxLength: 200, validator: 'string' as const },
  password: { name: 'Password', required: false, maxLength: 500, validator: 'string' as const },
  url: { name: 'URL', required: false, maxLength: 2000, validator: 'url' as const },
  category: { name: 'Category', required: false, maxLength: 50, validator: 'string' as const },
  notes: { name: 'Notes', required: false, maxLength: 2000, validator: 'string' as const },
};

router.get('/list', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const credentials = vaultStorage.listCredentials();

    res.json({
      success: true,
      data: credentials,
      count: credentials.length,
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to list credentials',
      message: 'An unexpected error occurred',
    });
  }
});

router.get('/search', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const querySchema = { name: 'query', required: true, maxLength: 100, validator: 'string' as const };
    const query = validateField(req.query.q, querySchema);
    if (!query.valid) {
      res.status(400).json({
        error: 'Invalid input',
        message: query.error,
      });
      return;
    }

    const results = vaultStorage.searchCredentials(query.value);

    res.json({
      success: true,
      data: results,
      count: results.length,
    });
  } catch (error) {
    res.status(500).json({
      error: 'Search failed',
      message: 'An unexpected error occurred',
    });
  }
});

router.get('/categories', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const categories = vaultStorage.getCategories();

    res.json({
      success: true,
      data: categories,
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get categories',
      message: 'An unexpected error occurred',
    });
  }
});

router.get('/:id', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const id = req.params.id;

    if (!id || typeof id !== 'string') {
      res.status(400).json({
        error: 'Invalid input',
        message: 'Credential ID is required',
      });
      return;
    }

    const credential = vaultStorage.getCredential(id);

    if (!credential) {
      res.status(404).json({
        error: 'Not found',
        message: 'Credential not found',
      });
      return;
    }

    logSecurityEvent({
      event: SecurityEvent.RECORD_VIEWED,
      userId: req.userId!,
      sessionId: req.sessionID,
      outcome: Outcome.SUCCESS,
      message: 'Credential viewed via web',
      metadata: { credentialId: id },
    });

    res.json({
      success: true,
      data: credential,
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get credential',
      message: 'An unexpected error occurred',
    });
  }
});

router.post('/add', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const validation = validateFields(req.body, CREDENTIAL_SCHEMA);
    if (!validation.valid) {
      res.status(400).json({ error: 'Invalid input', message: validation.error });
      return;
    }

    const credential = vaultStorage.addCredential({
      title: validation.data.title,
      username: validation.data.username,
      password: validation.data.password,
      url: validation.data.url || '',
      category: validation.data.category || 'General',
      notes: validation.data.notes || '',
    });

    logSecurityEvent({
      event: SecurityEvent.RECORD_ADDED,
      userId: req.userId!,
      sessionId: req.sessionID,
      outcome: Outcome.SUCCESS,
      message: 'Credential added via web',
      metadata: { credentialId: credential.id },
    });

    res.status(201).json({
      success: true,
      message: 'Credential added successfully',
      data: credential,
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to add credential',
      message: 'An unexpected error occurred',
    });
  }
});

router.put('/:id', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const id = req.params.id;

    if (!id) {
      res.status(400).json({
        error: 'Invalid input',
        message: 'Credential ID is required',
      });
      return;
    }

    const validation = validateFields(req.body, UPDATE_SCHEMA);
    if (!validation.valid) {
      res.status(400).json({ error: 'Invalid input', message: validation.error });
      return;
    }

    const updateData: Record<string, string | undefined> = {};
    for (const [field, value] of Object.entries(validation.data)) {
      if (value !== undefined && value !== '') {
        updateData[field] = value;
      }
    }

    const updated = vaultStorage.updateCredential(id, updateData);

    if (!updated) {
      res.status(404).json({
        error: 'Not found',
        message: 'Credential not found or access denied',
      });
      return;
    }

    logSecurityEvent({
      event: SecurityEvent.RECORD_UPDATED,
      userId: req.userId!,
      sessionId: req.sessionID,
      outcome: Outcome.SUCCESS,
      message: 'Credential updated via web',
      metadata: { credentialId: id },
    });

    res.json({
      success: true,
      message: 'Credential updated successfully',
      data: updated,
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to update credential',
      message: 'An unexpected error occurred',
    });
  }
});

router.delete('/:id', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const id = req.params.id;

    if (!id) {
      res.status(400).json({
        error: 'Invalid input',
        message: 'Credential ID is required',
      });
      return;
    }

    const deleted = vaultStorage.deleteCredential(id);

    if (!deleted) {
      res.status(404).json({
        error: 'Not found',
        message: 'Credential not found or access denied',
      });
      return;
    }

    logSecurityEvent({
      event: SecurityEvent.RECORD_DELETED,
      userId: req.userId!,
      sessionId: req.sessionID,
      outcome: Outcome.SUCCESS,
      message: 'Credential deleted via web',
      metadata: { credentialId: id },
    });

    res.json({
      success: true,
      message: 'Credential deleted successfully',
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to delete credential',
      message: 'An unexpected error occurred',
    });
  }
});

export { router as vaultRouter };

