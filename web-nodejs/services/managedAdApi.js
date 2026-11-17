'use strict';

// Scoped client for the optional managed-AD API. Keeping this separate avoids
// modifying BetterDesk's large general-purpose API client during an upgrade.
const axios = require('axios');
const http = require('http');
const https = require('https');
const config = require('../config/config');
const { assertSafeGoApiRelativePath } = require('../lib/goApiPath');

const isHttps = String(config.betterdeskApiUrl || '').startsWith('https://');
const client = axios.create({
    baseURL: config.betterdeskApiUrl,
    timeout: config.betterdeskApiTimeout,
    headers: {
        'Content-Type': 'application/json',
        'X-API-Key': config.betterdeskApiKey
    },
    ...(isHttps
        ? { httpsAgent: new https.Agent({ rejectUnauthorized: !config.allowSelfSignedCerts }) }
        : { httpAgent: new http.Agent({ keepAlive: true }) })
});

client.interceptors.request.use((requestConfig) => {
    if (requestConfig.url) {
        requestConfig.url = assertSafeGoApiRelativePath(String(requestConfig.url));
    }
    return requestConfig;
});

function wrap(data) {
    if (data && typeof data === 'object' && 'error' in data) {
        return { success: false, error: data.error };
    }
    return { success: true, data };
}

async function request(method, path, body) {
    try {
        const response = await client.request({ method, url: path, data: body });
        return wrap(response.data);
    } catch (error) {
        return {
            success: false,
            error: error.response?.data?.error || error.message
        };
    }
}

const peerPath = (peerID) => `/peers/${encodeURIComponent(peerID)}/managed-credential`;

module.exports = {
    getManagedCredential: (peerID) => request('get', peerPath(peerID)),
    rotateManagedCredential: (peerID, ttlMinutes) => request('post', peerPath(peerID), { ttl_minutes: ttlMinutes }),
    revokeManagedCredential: (peerID) => request('delete', peerPath(peerID)),
    getDirectoryConfig: () => request('get', '/directory/config'),
    saveDirectoryConfig: (body) => request('put', '/directory/config', body),
    syncDirectory: (apply) => request('post', '/directory/sync', { apply }),
    listDirectoryObjects: (kind, query) => request('get', `/directory/objects?kind=${encodeURIComponent(kind || '')}&q=${encodeURIComponent(query || '')}`)
};
