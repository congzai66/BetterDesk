/* Server-issued RustDesk temporary password UI. Independent of devices.js. */
(function () {
    'use strict';

    function text(en, zh) {
        return String(window.BetterDesk?.lang || '').toLowerCase().startsWith('zh') ? zh : en;
    }

    function hasPermission(name) {
        const user = window.BetterDesk?.user || {};
        const permissions = user.permissions || user.effective_permissions;
        if (Array.isArray(permissions)) return permissions.includes(name);
        const role = user.role || user.role_name;
        if (name === 'credential.rotate') return ['super_admin', 'admin', 'global_admin'].includes(role);
        return ['super_admin', 'admin', 'global_admin', 'operator'].includes(role);
    }

    function escape(value) {
        return Utils.escapeHtml(String(value ?? ''));
    }

    function injectAction() {
        if (!hasPermission('credential.view')) return;
        const menu = document.getElementById('devices-context-menu');
        const anchor = menu?.querySelector('[data-action="access-policy"]');
        if (!anchor || menu.querySelector('[data-action="managed-credential"]')) return;
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'kebab-menu-item';
        button.dataset.action = 'managed-credential';
        button.dataset.id = anchor.dataset.id || '';
        button.innerHTML = `<span class="material-icons">password</span><span>${text('Temporary password', '临时密码')}</span>`;
        anchor.insertAdjacentElement('afterend', button);
    }

    async function showModal(deviceId) {
        Modal.show({
            title: text('Server-issued temporary password', '服务端下发的临时密码'),
            content: `<div id="managed-credential-content"><p>${text('Loading credential status…', '正在读取密码状态…')}</p></div>`,
            buttons: [{ label: _('actions.close') || text('Close', '关闭'), class: 'btn-secondary', onClick: () => Modal.close() }]
        });
        await loadCredential(deviceId);
    }

    async function loadCredential(deviceId) {
        const container = document.getElementById('managed-credential-content');
        if (!container) return;
        try {
            const result = await Utils.api(`/api/devices/${encodeURIComponent(deviceId)}/managed-credential`);
            renderCredential(container, result?.data || result || {}, deviceId);
        } catch (error) {
            container.innerHTML = `<div class="alert alert-danger">${escape(error.message || 'Failed to load credential')}</div>`;
        }
    }

    function renderCredential(container, credential, deviceId) {
        const canRotate = hasPermission('credential.rotate');
        const status = credential.status || credential.state || 'none';
        const password = credential.password || '';
        container.innerHTML = `
            <div class="settings-form">
                <p class="form-hint">${text('The server issues a password only after the Windows agent confirms it. The agent replaces it with an unknown random password at expiry or revocation.', '只有 Windows 代理确认后，服务端才会提供新密码。到期或撤销时，代理会在本机换成未知随机密码。')}</p>
                <div class="form-row">
                    <div class="form-group"><label class="form-label">${text('Status', '状态')}</label><input class="form-input" readonly value="${escape(status)}"></div>
                    <div class="form-group"><label class="form-label">${text('Expires at', '到期时间')}</label><input class="form-input" readonly value="${escape(credential.expires_at || '—')}"></div>
                </div>
                ${password ? `<div class="form-group"><label class="form-label" for="managed-credential-password">${text('Temporary password', '临时密码')}</label>
                    <div style="display:flex;gap:8px;"><input class="form-input" id="managed-credential-password" type="password" readonly autocomplete="off" style="font-family:monospace;">
                    <button type="button" class="btn btn-secondary btn-sm" id="managed-credential-show">${text('Show', '显示')}</button>
                    <button type="button" class="btn btn-secondary btn-sm" id="managed-credential-copy">${text('Copy', '复制')}</button></div>
                </div>` : `<p class="form-hint">${text('No active viewable password.', '当前没有可查看的有效密码。')}</p>`}
                ${canRotate ? `<div class="form-group"><label class="form-label" for="managed-credential-ttl">${text('Validity', '有效期')}</label>
                    <select class="form-input" id="managed-credential-ttl"><option value="5">5 ${text('minutes', '分钟')}</option><option value="15" selected>15 ${text('minutes', '分钟')}</option><option value="30">30 ${text('minutes', '分钟')}</option><option value="60">60 ${text('minutes', '分钟')}</option><option value="120">120 ${text('minutes', '分钟')}</option></select></div>
                    <div class="form-actions" style="display:flex;gap:10px;"><button type="button" class="btn btn-primary" id="managed-credential-rotate"><span class="material-icons">sync</span>${text('Rotate now', '立即轮换')}</button>
                    <button type="button" class="btn btn-danger" id="managed-credential-revoke"><span class="material-icons">lock</span>${text('Revoke', '撤销')}</button></div>` : ''}
            </div>`;
        const input = document.getElementById('managed-credential-password');
        if (input) input.value = password;
        document.getElementById('managed-credential-show')?.addEventListener('click', (event) => {
            if (!input) return;
            const reveal = input.type === 'password';
            input.type = reveal ? 'text' : 'password';
            event.currentTarget.textContent = reveal ? text('Hide', '隐藏') : text('Show', '显示');
        });
        document.getElementById('managed-credential-copy')?.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(input?.value || '');
                Notifications.success(text('Copied', '已复制'));
            } catch (_) {
                input?.select();
                document.execCommand('copy');
            }
        });
        document.getElementById('managed-credential-rotate')?.addEventListener('click', async () => {
            const ttl = Number(document.getElementById('managed-credential-ttl')?.value || 15);
            if (!await Modal.confirm({
                title: text('Rotate temporary password?', '确认轮换临时密码？'),
                message: text('The current password will stop working. The online Windows agent must confirm the change before the new password is shown.', '当前密码将失效。只有在线 Windows 代理确认修改后，才会显示新密码。'),
                confirmLabel: text('Rotate', '轮换')
            })) return showModal(deviceId);
            try {
                await Utils.api(`/api/devices/${encodeURIComponent(deviceId)}/managed-credential`, { method: 'POST', body: { ttl_minutes: ttl } });
                Notifications.success(text('Temporary password rotated', '临时密码已轮换'));
            } catch (error) {
                Notifications.error(error.message || text('Rotation failed', '轮换失败'));
            }
            await showModal(deviceId);
        });
        document.getElementById('managed-credential-revoke')?.addEventListener('click', async () => {
            if (!await Modal.confirm({
                title: text('Revoke temporary password?', '确认撤销临时密码？'),
                message: text('The online agent will immediately replace it with an unknown random password.', '在线代理会立即将其替换为未知随机密码。'),
                confirmLabel: text('Revoke', '撤销'), danger: true
            })) return showModal(deviceId);
            try {
                await Utils.api(`/api/devices/${encodeURIComponent(deviceId)}/managed-credential`, { method: 'DELETE', body: {} });
                Notifications.success(text('Temporary password revoked', '临时密码已撤销'));
            } catch (error) {
                Notifications.error(error.message || text('Revocation failed', '撤销失败'));
            }
            await showModal(deviceId);
        });
    }

    function init() {
        injectAction();
        const menu = document.getElementById('devices-context-menu');
        if (menu) new MutationObserver(injectAction).observe(menu, { childList: true, subtree: true });
        document.addEventListener('click', (event) => {
            const button = event.target.closest('[data-action="managed-credential"]');
            if (!button) return;
            event.preventDefault();
            event.stopImmediatePropagation();
            if (button.dataset.id) showModal(button.dataset.id);
        }, true);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
