// Key/session backup dialog. Dependencies are supplied by the shared page;
// the same source is inlined in the desktop and Android distribution.
window.LinSCPKeySession = {
  create({ $, t, state, openModal, apiPost, loadLocal, loadSessions,
    refreshSshKeyVaultPicker, readFileAsArrayBuffer, bytesToBase64 }) {
    function startsWithMagic(bytes, magic) {
      if (bytes.length < magic.length) return false;
      for (let i = 0; i < magic.length; i++) {
        if (bytes[i] !== magic[i]) return false;
      }
      return true;
    }
    const KEY_SESSION_MAGIC = [76, 83, 67, 80, 86, 76, 84, 50]; // 'LSCPVLT2' 
    function siteSubline(site) {
      const proto = site.protocol || 'sftp';
      if (proto === 'local') {
        const left = site.local_dir || '';
        const right = site.other_local_dir || '';
        return left && right ? 'local · ' + left + ' ↔ ' + right : (left ? 'local · ' + left : 'local');
      }
      const host = site.host || '';
      const port = site.port ? ':' + site.port : '';
      const user = site.username ? site.username + '@' : '';
      return host ? proto + '://' + user + host + port : proto;
    }
    function renderKeySessionRows(list, entries, emptyText) {
      list.innerHTML = '';
      if (!entries.length) {
        const row = document.createElement('div');
        row.className = 'hint';
        row.textContent = emptyText;
        list.appendChild(row);
        return;
      }
      for (const entry of entries) {
        const row = document.createElement('label');
        row.className = 'site-item';
        row.style.cursor = 'pointer';
        const box = document.createElement('input');
        box.type = 'checkbox';
        box.checked = true;
        box.dataset.name = entry.name;
        row.appendChild(box);
        const label = document.createElement('span');
        label.textContent = entry.name;
        row.appendChild(label);
        const detail = document.createElement('span');
        detail.className = 'hint';
        detail.style.marginLeft = 'auto';
        const bits = [siteSubline(entry)];
        if (entry.has_password) bits.push(t('Password'));
        if (entry.has_key_passphrase) bits.push(t('Key password'));
        if (entry.has_ssh_key) bits.push(t('SSH key'));
        if (entry.exists_in_store) bits.push(t('Already saved'));
        detail.textContent = bits.join(' · ');
        row.appendChild(detail);
        list.appendChild(row);
      }
    }
    function tickedNames(selector) {
      return Array.from(document.querySelectorAll(selector + ' input[type="checkbox"]:checked'))
        .map(box => box.dataset.name);
    }
    function setKeyExportSelection(checked) {
      document.querySelectorAll('#keyExportList input[type="checkbox"]').forEach(box => { box.checked = checked; });
    }
    function setKeyImportSelection(checked) {
      document.querySelectorAll('#keyImportList input[type="checkbox"]').forEach(box => { box.checked = checked; });
    }
    let keyImportScanState = { base64: '', fingerprint: '', vaultKeyCount: 0 };
    async function openKeySessionExport() {
      $('keyExportStatus').textContent = '';
      $('keyExportPassword').value = '';
      $('keyExportPasswordConfirm').value = '';
      $('keyExportIncludeVaultKeys').checked = true;
      const list = $('keyExportList');
      list.innerHTML = '';
      openModal('keySessionExportModal');
      await loadSessions();
      const entries = (state.sessions || []).map(site => ({
        name: site.name,
        protocol: site.protocol,
        host: site.host,
        port: site.port,
        username: site.username,
        local_dir: site.local_dir || '',
        other_local_dir: site.other_local_dir || '',
        has_password: !!(site.has_password || site.has_proxy_password || site.has_tunnel_password),
        has_key_passphrase: !!(site.has_key_passphrase || site.has_tunnel_passphrase),
        has_ssh_key: !!(
          site.private_key ||
          site.keyfile ||
          site.tunnel_private_key ||
          site.linscp_public_key_file ||
          site.linscp_tunnel_public_key_file ||
          (site.tunnel && site.tunnel.keyfile)
        ),
      }));
      renderKeySessionRows(list, entries, t('There are no saved sessions to export.'));
    }
    async function exportKeySession() {
      const password = $('keyExportPassword').value;
      if (!password) { $('keyExportStatus').textContent = t('Choose a non-empty backup password.'); return; }
      if (password !== $('keyExportPasswordConfirm').value) { $('keyExportStatus').textContent = t('The backup passwords do not match.'); return; }
      const names = tickedNames('#keyExportList');
      const includeVaultKeys = $('keyExportIncludeVaultKeys').checked;
      if (!names.length && !includeVaultKeys) { $('keyExportStatus').textContent = t('Select at least one session to export.'); return; }
      $('keyExportStatus').textContent = t('Exporting…');
      try {
        const data = await apiPost('/api/vault/export', {
          password: password,
          plain_text: false,
          sessions: names,
          include_vault_keys: includeVaultKeys,
          save_dir: (state.local && state.local.path) || '',
        });
        if (!data || !data.success) { $('keyExportStatus').textContent = data && data.error || t('Export failed'); return; }
        if (data.saved_path) {
          if (state.local && state.local.path) await loadLocal(state.local.path);
        } else {
          const raw = atob(data.data_base64);
          const bytes = new Uint8Array(raw.length);
          for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
          const objectUrl = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
          bytes.fill(0);
          const link = document.createElement('a');
          link.href = objectUrl;
          link.download = data.filename;
          document.body.appendChild(link);
          link.click();
          link.remove();
          setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
        }
        $('keyExportStatus').textContent = t('Encrypted export written: {filename} ({count} entries).', { filename: data.filename, count: data.entry_count });
        $('keyExportPassword').value = '';
        $('keyExportPasswordConfirm').value = '';
      } catch(e) { $('keyExportStatus').textContent = String(e); }
    }
    function keyImportFileChanged() {
      keyImportScanState = { base64: '', fingerprint: '', vaultKeyCount: 0 };
      $('keyImportStatus').textContent = '';
      $('keyImportList').innerHTML = '';
      $('keyImportVaultKeys').textContent = '';
    }
    async function readKeyImportBackup() {
      const file = $('keyImportFile').files && $('keyImportFile').files[0];
      if (!file) throw new Error(t('Choose a key/session backup file first.'));
      if (file.size > 16 * 1024 * 1024) throw new Error(t('Key/Session backups are limited to 16 MiB.'));
      const bytes = new Uint8Array(await readFileAsArrayBuffer(file));
      return { bytes, base64: bytesToBase64(bytes) };
    }
    async function scanKeySessionBackup() {
      const password = $('keyImportPassword').value;
      keyImportScanState = { base64: '', fingerprint: '', vaultKeyCount: 0 };
      $('keyImportStatus').textContent = t('Reading...');
      $('keyImportList').innerHTML = '';
      $('keyImportVaultKeys').textContent = '';
      try {
        const { bytes, base64 } = await readKeyImportBackup();
        const encrypted = startsWithMagic(bytes, KEY_SESSION_MAGIC);
        bytes.fill(0);
        if (encrypted && !password) {
          $('keyImportStatus').textContent = t('This is an encrypted backup. Enter its password, then choose Read backup.');
          return;
        }
        const data = await apiPost('/api/vault/scan', { password, data_base64: base64 });
        if (!data || !data.success) { $('keyImportStatus').textContent = data && data.error || t('The backup could not be read.'); return; }
        keyImportScanState = { base64, fingerprint: data.fingerprint || '', vaultKeyCount: data.vault_key_count || 0 };
        $('keyImportVaultKeys').textContent = t('Vault SSH keys in backup: {count}', {count: keyImportScanState.vaultKeyCount});
        const total = data.entry_count || 0;
        const ignored = data.ignored_entries || 0;
        $('keyImportStatus').textContent = ignored
          ? t('Found {count} session(s) in the backup; {ignored} unsupported entries were ignored.', { count: total, ignored })
          : t('Found {count} session(s) in the backup.', { count: total });
        renderKeySessionRows($('keyImportList'), data.entries || [], t('The backup contains no LinSCP sessions.'));
      } catch(e) { $('keyImportStatus').textContent = String(e && e.message ? e.message : e); }
    }
    async function openKeySessionImport() {
      keyImportScanState = { base64: '', fingerprint: '', vaultKeyCount: 0 };
      $('keyImportStatus').textContent = '';
      $('keyImportPassword').value = '';
      $('keyImportFile').value = '';
      $('keyImportReplace').checked = false;
      $('keyImportList').innerHTML = '';
      $('keyImportVaultKeys').textContent = '';
      openModal('keySessionImportModal');
    }
    async function importKeySession() {
      const file = $('keyImportFile').files && $('keyImportFile').files[0];
      if (!file) { $('keyImportStatus').textContent = t('Choose a key/session backup file first.'); return; }
      const password = $('keyImportPassword').value;
      const names = tickedNames('#keyImportList');
      if (!names.length && !keyImportScanState.vaultKeyCount) { $('keyImportStatus').textContent = t('Select at least one session to import.'); return; }
      const replace = $('keyImportReplace').checked;
      if (replace && !confirm(t('Sessions whose names match will be overwritten. Continue?'))) return;
      $('keyImportStatus').textContent = t('Importing…');
      try {
        const { bytes, base64 } = await readKeyImportBackup();
        bytes.fill(0);
        if (!keyImportScanState.base64) {
          $('keyImportStatus').textContent = t('Read the backup before importing.');
          return;
        }
        if (base64 !== keyImportScanState.base64) {
          $('keyImportStatus').textContent = t('The selected backup file changed since it was read. Read the backup again before importing.');
          return;
        }
        const payload = {
          password,
          data_base64: base64,
          replace,
          sessions: names,
        };
        if (keyImportScanState.fingerprint) payload.fingerprint = keyImportScanState.fingerprint;
        const data = await apiPost('/api/vault/import', payload);
        if (!data || !data.success) { $('keyImportStatus').textContent = data && data.error || t('Import failed'); return; }
        const restoredVaultKeys = keyImportScanState.vaultKeyCount;
        keyImportScanState = { base64: '', fingerprint: '', vaultKeyCount: 0 };
        $('keyImportVaultKeys').textContent = '';
        $('keyImportStatus').textContent = t('Imported {count} session(s); skipped {skipped} existing and ignored {ignored} unsupported entries.', {
          count: data.imported, skipped: data.skipped_existing, ignored: data.ignored_entries,
        });
        $('keyImportPassword').value = '';
        $('keyImportFile').value = '';
        await loadSessions();
        if (((data.imported || 0) > 0 || restoredVaultKeys > 0) && $('sshKeyVaultModal').classList.contains('open')) {
          await refreshSshKeyVaultPicker();
        }
      } catch(e) { $('keyImportStatus').textContent = String(e && e.message ? e.message : e); }
    }

    return {
      openKeySessionExport, exportKeySession, setKeyExportSelection,
      openKeySessionImport, importKeySession, setKeyImportSelection,
      keyImportFileChanged, scanKeySessionBackup,
    };
  },
};
