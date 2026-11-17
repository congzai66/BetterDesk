/* BetterDesk managed Active Directory inventory panel. */
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
        if (name === 'directory.sync') return ['super_admin', 'admin', 'global_admin'].includes(role);
        return ['super_admin', 'admin', 'global_admin', 'operator'].includes(role);
    }

    function escape(value) {
        return Utils.escapeHtml(String(value ?? ''));
    }

    function init() {
        const button = document.getElementById('ad-directory-btn');
        if (!button) return;
        if (!hasPermission('directory.view')) {
            button.style.display = 'none';
            return;
        }
        button.addEventListener('click', openDirectoryModal);
    }

    async function openDirectoryModal() {
        const canSync = hasPermission('directory.sync');
        Modal.show({
            title: text('Active Directory devices & OUs', 'Active Directory 设备与 OU'),
            content: `<div id="ad-directory-content"><p>${text('Loading directory…', '正在加载目录…')}</p></div>`,
            buttons: [{ label: _('actions.close') || text('Close', '关闭'), class: 'btn-secondary', onClick: () => Modal.close() }]
        });
        await loadDirectory(canSync);
    }

    async function loadDirectory(canSync) {
        const container = document.getElementById('ad-directory-content');
        if (!container) return;
        try {
            const type = document.getElementById('ad-object-type')?.value || '';
            const [configResult, objectsResult] = await Promise.all([
                Utils.api('/api/settings/directory'),
                Utils.api('/api/settings/directory/objects' + (type ? `?type=${encodeURIComponent(type)}` : ''))
            ]);
            const config = configResult?.data || configResult || {};
            const objects = objectsResult?.data?.objects || objectsResult?.objects || [];
            container.innerHTML = `
                <div class="settings-form">
                    <p class="form-hint">${text('Read-only AD synchronization imports users, groups, computers and OUs. Computers match RustDesk peers by hostname; only explicitly mapped OUs can assign organizations.', '只读同步 AD 用户、组、计算机和 OU。计算机按主机名匹配 RustDesk 设备，只有明确映射的 OU 才能分配组织。')}</p>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label" for="ad-sync-interval">${text('Sync interval (minutes, 0 = manual)', '同步间隔（分钟，0 = 仅手动）')}</label>
                            <input class="form-input" id="ad-sync-interval" type="number" min="0" max="1440" value="${escape(config.sync_interval_minutes || 0)}" ${canSync ? '' : 'disabled'}>
                        </div>
                        <div class="form-group">
                            <label class="form-label" for="ad-apply-assignments">
                                <input id="ad-apply-assignments" type="checkbox" ${config.apply_mappings ? 'checked' : ''} ${canSync ? '' : 'disabled'}>
                                ${text('Apply mapped organization assignments', '应用已映射的组织分配')}
                            </label>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="ad-ou-mappings">${text('OU mappings — one per line: OU DN | Organization ID', 'OU 映射——每行：OU DN | 组织 ID')}</label>
                        <textarea class="form-input form-textarea" id="ad-ou-mappings" rows="5" ${canSync ? '' : 'disabled'} placeholder="OU=Finance,DC=example,DC=com | 12">${escape(config.ou_org_map || '')}</textarea>
                    </div>
                    <div class="form-actions" style="display:flex;gap:10px;flex-wrap:wrap;">
                        ${canSync ? `<button type="button" class="btn btn-primary btn-sm" id="ad-save-btn"><span class="material-icons">save</span>${text('Save configuration', '保存配置')}</button>
                        <button type="button" class="btn btn-secondary btn-sm" id="ad-sync-btn"><span class="material-icons">sync</span>${text('Sync now', '立即同步')}</button>` : ''}
                        <span id="ad-directory-status" class="form-hint">${config.last_sync_at ? `${text('Last sync', '上次同步')}: ${escape(config.last_sync_at)} (${escape(config.last_sync_status || 'ok')})` : text('Not synchronized yet', '尚未同步')}</span>
                    </div>
                    <hr>
                    <div class="form-row" style="align-items:end;">
                        <div class="form-group">
                            <label class="form-label" for="ad-object-type">${text('Directory object type', '目录对象类型')}</label>
                            <select class="form-input" id="ad-object-type">
                                <option value="">${text('All', '全部')}</option>
                                <option value="computer" ${type === 'computer' ? 'selected' : ''}>${text('Computers', '计算机')}</option>
                                <option value="ou" ${type === 'ou' ? 'selected' : ''}>OU</option>
                                <option value="user" ${type === 'user' ? 'selected' : ''}>${text('Users', '用户')}</option>
                                <option value="group" ${type === 'group' ? 'selected' : ''}>${text('Groups', '组')}</option>
                            </select>
                        </div>
                    </div>
                    <div style="max-height:360px;overflow:auto;">
                        <table class="data-table"><thead><tr>
                            <th>${text('Name', '名称')}</th><th>${text('Type', '类型')}</th><th>OU / DN</th><th>Peer ID</th><th>Org ID</th><th>${text('Status', '状态')}</th>
                        </tr></thead><tbody>
                        ${objects.length ? objects.map(obj => `<tr>
                            <td>${escape(obj.name)}</td><td>${escape(obj.kind)}</td><td>${escape(obj.ou || obj.dn)}</td>
                            <td>${escape(obj.peer_id)}</td><td>${escape(obj.org_id)}</td><td>${escape(obj.match_state || '—')}</td>
                        </tr>`).join('') : `<tr><td colspan="6">${text('No directory objects. Configure LDAP and run a sync.', '暂无目录对象，请配置 LDAP 并执行同步。')}</td></tr>`}
                        </tbody></table>
                    </div>
                </div>`;
            document.getElementById('ad-object-type')?.addEventListener('change', () => loadDirectory(canSync));
            document.getElementById('ad-save-btn')?.addEventListener('click', () => saveDirectory(canSync));
            document.getElementById('ad-sync-btn')?.addEventListener('click', syncNow);
        } catch (error) {
            container.innerHTML = `<div class="alert alert-danger">${escape(error.message || text('Failed to load directory', '目录加载失败'))}</div>`;
        }
    }

    function directoryPayload() {
        return {
            sync_interval_minutes: Number(document.getElementById('ad-sync-interval')?.value || 0),
            apply_mappings: !!document.getElementById('ad-apply-assignments')?.checked,
            ou_org_map: document.getElementById('ad-ou-mappings')?.value || ''
        };
    }

    async function saveDirectory(canSync) {
        try {
            await Utils.api('/api/settings/directory', { method: 'PUT', body: directoryPayload() });
            Notifications.success(text('Directory configuration saved', '目录配置已保存'));
            await loadDirectory(canSync);
        } catch (error) {
            Notifications.error(error.message || text('Save failed', '保存失败'));
        }
    }

    async function syncNow() {
        const button = document.getElementById('ad-sync-btn');
        if (button) button.disabled = true;
        try {
            await Utils.api('/api/settings/directory/sync', {
                method: 'POST', body: { apply_assignments: !!document.getElementById('ad-apply-assignments')?.checked }
            });
            Notifications.success(text('AD synchronization completed', 'AD 同步已完成'));
        } catch (error) {
            Notifications.error(error.message || text('Synchronization failed', '同步失败'));
        } finally {
            await loadDirectory(true);
        }
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
