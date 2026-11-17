'use strict';

const express = require('express');
const router = express.Router();
const db = require('../services/database');
const serverBackend = require('../services/serverBackend');
const deviceGroupService = require('../services/deviceGroupService');
const managedAdApi = require('../services/managedAdApi');
const { requireAuth, requirePermission } = require('../middleware/auth');
const { plainBodyObject } = require('../lib/bodyScalars');

async function scopedDevice(req, res) {
    const device = await serverBackend.getDeviceById(req.params.id);
    if (!device) {
        res.status(404).json({ success: false, error: req.t('devices.not_found') });
        return null;
    }
    if (!await deviceGroupService.userCanAccessDevice(db, req.session.user, device)) {
        res.status(403).json({ success: false, error: req.t('errors.forbidden') });
        return null;
    }
    return device;
}

function sendUpstream(res, result, failureStatus = 502) {
    return res.status(result.success ? 200 : failureStatus).json(result);
}

router.get('/api/devices/:id/managed-credential', requireAuth, requirePermission('credential.view'), async (req, res) => {
    try {
        if (!await scopedDevice(req, res)) return;
        sendUpstream(res, await managedAdApi.getManagedCredential(req.params.id));
    } catch (error) {
        console.error('Get managed credential error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to get managed credential status' });
    }
});

router.post('/api/devices/:id/managed-credential', requireAuth, requirePermission('credential.rotate'), async (req, res) => {
    try {
        if (!await scopedDevice(req, res)) return;
        const body = plainBodyObject(req.body || {});
        const result = await managedAdApi.rotateManagedCredential(req.params.id, body.ttl_minutes);
        if (result.success) {
            await db.logAction(req.session.userId, 'managed_credential_rotated', `Rotated managed credential for device ${req.params.id}`, req.ip);
        }
        sendUpstream(res, result);
    } catch (error) {
        console.error('Rotate managed credential error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to rotate managed credential' });
    }
});

router.delete('/api/devices/:id/managed-credential', requireAuth, requirePermission('credential.rotate'), async (req, res) => {
    try {
        if (!await scopedDevice(req, res)) return;
        const result = await managedAdApi.revokeManagedCredential(req.params.id);
        if (result.success) {
            await db.logAction(req.session.userId, 'managed_credential_revoked', `Revoked managed credential for device ${req.params.id}`, req.ip);
        }
        sendUpstream(res, result);
    } catch (error) {
        console.error('Revoke managed credential error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to revoke managed credential' });
    }
});

router.get('/api/settings/directory', requireAuth, requirePermission('directory.view'), async (_req, res) => {
    sendUpstream(res, await managedAdApi.getDirectoryConfig());
});

router.put('/api/settings/directory', requireAuth, requirePermission('directory.sync'), async (req, res) => {
    try {
        const result = await managedAdApi.saveDirectoryConfig(plainBodyObject(req.body || {}));
        if (result.success) {
            await db.logAction(req.session.userId, 'directory_config_updated', 'Updated AD synchronization and OU mapping configuration', req.ip);
        }
        sendUpstream(res, result);
    } catch (error) {
        console.error('Save directory config error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to save directory configuration' });
    }
});

router.post('/api/settings/directory/sync', requireAuth, requirePermission('directory.sync'), async (req, res) => {
    try {
        const body = plainBodyObject(req.body || {});
        const result = await managedAdApi.syncDirectory(body.apply_assignments);
        if (result.success) {
            await db.logAction(req.session.userId, 'directory_sync_started', 'Completed manual AD inventory synchronization', req.ip);
        }
        sendUpstream(res, result);
    } catch (error) {
        console.error('Directory sync error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to synchronize directory' });
    }
});

router.get('/api/settings/directory/objects', requireAuth, requirePermission('directory.view'), async (req, res) => {
    sendUpstream(res, await managedAdApi.listDirectoryObjects(req.query?.type, req.query?.q));
});

module.exports = router;
