'use strict';

const request = require('supertest');
const { createTestApp } = require('./helpers');

jest.mock('../services/database', () => ({ logAction: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../services/serverBackend', () => ({ getDeviceById: jest.fn() }));
jest.mock('../services/deviceGroupService', () => ({ userCanAccessDevice: jest.fn() }));
jest.mock('../services/managedAdApi', () => ({
    getManagedCredential: jest.fn(),
    rotateManagedCredential: jest.fn(),
    revokeManagedCredential: jest.fn(),
    getDirectoryConfig: jest.fn(),
    saveDirectoryConfig: jest.fn(),
    syncDirectory: jest.fn(),
    listDirectoryObjects: jest.fn()
}));

const serverBackend = require('../services/serverBackend');
const deviceGroupService = require('../services/deviceGroupService');
const api = require('../services/managedAdApi');
const routes = require('../routes/managedAd.routes');

function appFor(role, permissions = []) {
    const app = createTestApp();
    app.use((req, _res, next) => {
        req.session.userId = 7;
        req.session.user = { id: 7, username: 'tester', role };
        req.effectivePermissions = new Set(permissions);
        next();
    });
    app.use('/', routes);
    return app;
}

describe('managed AD route authorization and mapping', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        serverBackend.getDeviceById.mockResolvedValue({ id: 'PEER01', hostname: 'PC01' });
        deviceGroupService.userCanAccessDevice.mockResolvedValue(true);
        api.getManagedCredential.mockResolvedValue({ success: true, data: { state: 'none' } });
        api.rotateManagedCredential.mockResolvedValue({ success: true, data: { state: 'active' } });
        api.syncDirectory.mockResolvedValue({ success: true, data: { total: 1 } });
    });

    test('denies credential reads without credential.view', async () => {
        const response = await request(appFor('viewer')).get('/api/devices/PEER01/managed-credential');
        expect(response.status).toBe(403);
        expect(api.getManagedCredential).not.toHaveBeenCalled();
    });

    test('enforces device scope before reading a credential', async () => {
        deviceGroupService.userCanAccessDevice.mockResolvedValue(false);
        const response = await request(appFor('operator', ['credential.view'])).get('/api/devices/PEER01/managed-credential');
        expect(response.status).toBe(403);
        expect(api.getManagedCredential).not.toHaveBeenCalled();
    });

    test('allows an authorized scoped credential read', async () => {
        const response = await request(appFor('operator', ['credential.view'])).get('/api/devices/PEER01/managed-credential');
        expect(response.status).toBe(200);
        expect(api.getManagedCredential).toHaveBeenCalledWith('PEER01');
    });

    test('requires credential.rotate and forwards TTL', async () => {
        const denied = await request(appFor('operator', ['credential.view']))
            .post('/api/devices/PEER01/managed-credential').send({ ttl_minutes: 15 });
        expect(denied.status).toBe(403);
        const allowed = await request(appFor('global_admin', ['credential.rotate']))
            .post('/api/devices/PEER01/managed-credential').send({ ttl_minutes: 30 });
        expect(allowed.status).toBe(200);
        expect(api.rotateManagedCredential).toHaveBeenCalledWith('PEER01', 30);
    });

    test('maps Console apply_assignments to Go apply', async () => {
        const response = await request(appFor('global_admin', ['directory.sync']))
            .post('/api/settings/directory/sync').send({ apply_assignments: true });
        expect(response.status).toBe(200);
        expect(api.syncDirectory).toHaveBeenCalledWith(true);
    });
});
