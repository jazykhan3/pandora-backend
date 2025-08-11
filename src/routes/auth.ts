import express from 'express';
import argon2 from 'argon2';
import speakeasy from 'speakeasy';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import db from '../db';
import { authenticateToken, generateToken, AuthenticatedRequest } from '../middleware/authMiddleware';
import { logAuditEvent } from '../middleware/auditLogger';

const router = express.Router();

// Helper: generate random invite code
function generateInviteCode(): string {
  return crypto.randomBytes(16).toString('hex');
}

// Create Organization & Admin user
router.post('/orgs', async (req, res) => {
  const { orgName, industry, size, fullName, email, password } = req.body;

  if (!orgName || !fullName || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Create org
    const orgId = uuidv4();
    const orgStmt = db.prepare(`
      INSERT INTO organizations (id, name, industry, size) 
      VALUES (?, ?, ?, ?)
    `);
    orgStmt.run(orgId, orgName, industry, size);

    // Hash password
    const passwordHash = await argon2.hash(password);

    // Create user
    const userId = uuidv4();
    const userStmt = db.prepare(`
      INSERT INTO users (id, full_name, email, password_hash) 
      VALUES (?, ?, ?, ?)
    `);
    userStmt.run(userId, fullName, email.toLowerCase(), passwordHash);

    // Add user as admin member to org
    const memberStmt = db.prepare(`
      INSERT INTO team_members (id, user_id, org_id, role) 
      VALUES (?, ?, ?, 'Admin')
    `);
    memberStmt.run(uuidv4(), userId, orgId);

    // Log audit event
    await logAuditEvent({
      userId,
      orgId,
      action: `Created organization '${orgName}' and admin user`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { orgName, email }
    });

    // Generate JWT token
    const token = generateToken({ userId, orgId, role: 'Admin' });

    res.json({ 
      message: 'Organization and admin user created', 
      token, 
      orgId, 
      userId,
      role: 'Admin'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Validate invite code
router.get('/invites/validate', async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).json({ error: 'Invite code required' });
  }

  try {
    const stmt = db.prepare(`
      SELECT i.*, o.name as org_name 
      FROM invites i 
      JOIN organizations o ON i.org_id = o.id
      WHERE i.code = ? AND i.expires_at > ? AND i.used_at IS NULL
    `);
    const invite = stmt.get(code, Math.floor(Date.now() / 1000));

    if (!invite) {
      return res.status(400).json({ error: 'Invalid or expired invite code' });
    }

    res.json({ 
      valid: true, 
      orgId: invite.org_id, 
      orgName: invite.org_name,
      role: invite.role,
      email: invite.email
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// User signup via invite
router.post('/invites/accept', async (req, res) => {
  const { code, fullName, email, password } = req.body;

  if (!code || !fullName || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Validate invite code
    const inviteStmt = db.prepare(`
      SELECT * FROM invites 
      WHERE code = ? AND expires_at > ? AND used_at IS NULL
    `);
    const invite = inviteStmt.get(code, Math.floor(Date.now() / 1000));

    if (!invite) {
      return res.status(400).json({ error: 'Invalid or expired invite code' });
    }

    if (invite.email.toLowerCase() !== email.toLowerCase()) {
      return res.status(400).json({ error: 'Email does not match invite' });
    }

    // Hash password
    const passwordHash = await argon2.hash(password);

    // Create user
    const userId = uuidv4();
    const userStmt = db.prepare(`
      INSERT INTO users (id, full_name, email, password_hash) 
      VALUES (?, ?, ?, ?)
    `);
    userStmt.run(userId, fullName, email.toLowerCase(), passwordHash);

    // Add user to org with role from invite
    const memberStmt = db.prepare(`
      INSERT INTO team_members (id, user_id, org_id, role) 
      VALUES (?, ?, ?, ?)
    `);
    memberStmt.run(uuidv4(), userId, invite.org_id, invite.role);

    // Mark invite as used
    const updateStmt = db.prepare(`
      UPDATE invites SET used_at = ? WHERE id = ?
    `);
    updateStmt.run(Math.floor(Date.now() / 1000), invite.id);

    // Log audit event
    await logAuditEvent({
      userId,
      orgId: invite.org_id,
      action: `User joined organization via invite with role ${invite.role}`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { email, inviteCode: code }
    });

    // Generate JWT token
    const token = generateToken({ userId, orgId: invite.org_id, role: invite.role });

    res.json({ 
      message: 'User created and added to organization', 
      token, 
      userId, 
      orgId: invite.org_id, 
      role: invite.role 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 2FA Setup: generate TOTP secret
router.post('/setup-2fa', authenticateToken, async (req: AuthenticatedRequest, res) => {
  try {
    const secret = speakeasy.generateSecret({ 
      length: 20,
      name: 'Pandaura AS',
      issuer: 'Pandaura AS'
    });

    // Save secret to user for later verification
    const stmt = db.prepare(`
      UPDATE users SET totp_secret = ? WHERE id = ?
    `);
    stmt.run(secret.base32, req.user!.userId);

    // Log audit event
    await logAuditEvent({
      userId: req.user!.userId,
      action: 'Initiated 2FA setup',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({ 
      secret: secret.base32, 
      otpauth_url: secret.otpauth_url 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 2FA Verification
router.post('/verify-2fa', authenticateToken, async (req: AuthenticatedRequest, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Missing 2FA token' });
  }

  try {
    const stmt = db.prepare(`SELECT totp_secret FROM users WHERE id = ?`);
    const user = stmt.get(req.user!.userId) as { totp_secret: string } | undefined;

    if (!user || !user.totp_secret) {
      return res.status(404).json({ error: 'User not found or 2FA not set up' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      // Log failed attempt
      await logAuditEvent({
        userId: req.user!.userId,
        action: 'Failed 2FA verification attempt',
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      return res.status(400).json({ error: 'Invalid 2FA token' });
    }

    // Enable 2FA for user
    const updateStmt = db.prepare(`
      UPDATE users SET two_factor_enabled = 1 WHERE id = ?
    `);
    updateStmt.run(req.user!.userId);

    // Log successful verification
    await logAuditEvent({
      userId: req.user!.userId,
      action: 'Successfully verified and enabled 2FA',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({ success: true, message: '2FA verified and enabled' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Device binding endpoint
router.post('/device-bind', authenticateToken, async (req: AuthenticatedRequest, res) => {
  const { instanceId, deviceFingerprintHash } = req.body;

  if (!instanceId || !deviceFingerprintHash) {
    return res.status(400).json({ error: 'Missing device binding info' });
  }

  try {
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO device_bindings (id, user_id, instance_id, device_fingerprint_hash) 
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(uuidv4(), req.user!.userId, instanceId, deviceFingerprintHash);

    // Log audit event
    await logAuditEvent({
      userId: req.user!.userId,
      action: 'Device bound to account',
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { instanceId }
    });

    res.json({ success: true, message: 'Device bound successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to bind device' });
  }
});

// User login
router.post('/login', async (req, res) => {
  const { email, password, twoFactorToken } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const userStmt = db.prepare(`
      SELECT * FROM users 
      WHERE email = ? AND is_active = 1
    `);
    const user = userStmt.get(email.toLowerCase());

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await argon2.verify(user.password_hash, password);
    if (!validPassword) {
      // Log failed login attempt
      await logAuditEvent({
        userId: user.id,
        action: 'Failed login attempt - invalid password',
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { email }
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check 2FA if enabled
    if (user.two_factor_enabled && user.totp_secret) {
      if (!twoFactorToken) {
        return res.status(200).json({ 
          requiresTwoFactor: true,
          message: 'Two-factor authentication required'
        });
      }

      const verified = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: twoFactorToken,
        window: 1
      });

      if (!verified) {
        // Log failed 2FA attempt
        await logAuditEvent({
          userId: user.id,
          action: 'Failed login attempt - invalid 2FA token',
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          metadata: { email }
        });
        return res.status(401).json({ error: 'Invalid two-factor authentication token' });
      }
    }

    // Fetch user's organizations & roles
    const orgsStmt = db.prepare(`
      SELECT tm.org_id, tm.role, o.name as org_name 
      FROM team_members tm 
      JOIN organizations o ON tm.org_id = o.id
      WHERE tm.user_id = ?
    `);
    const userOrgs = orgsStmt.all(user.id);

    if (userOrgs.length === 0) {
      return res.status(403).json({ error: 'No organization membership found' });
    }

    // Use first org as default (or implement org selection logic)
    const primaryOrg = userOrgs[0];

    // Log successful login
    await logAuditEvent({
      userId: user.id,
      orgId: primaryOrg.org_id,
      action: 'Successful login',
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { email, orgName: primaryOrg.org_name }
    });

    // Generate JWT
    const token = generateToken({ 
      userId: user.id, 
      orgId: primaryOrg.org_id, 
      role: primaryOrg.role 
    });

    res.json({ 
      token, 
      userId: user.id, 
      orgId: primaryOrg.org_id, 
      role: primaryOrg.role,
      orgName: primaryOrg.org_name,
      organizations: userOrgs,
      message: 'Login successful' 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's organizations
router.get('/users/:userId/orgs', authenticateToken, async (req: AuthenticatedRequest, res) => {
  const { userId } = req.params;

  // Ensure user can only access their own org list or is admin
  if (req.user!.userId !== userId) {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const stmt = db.prepare(`
      SELECT tm.org_id, tm.role, o.name as org_name, o.industry, o.size
      FROM team_members tm 
      JOIN organizations o ON tm.org_id = o.id
      WHERE tm.user_id = ?
    `);
    const orgs = stmt.all(userId);

    res.json(orgs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;
