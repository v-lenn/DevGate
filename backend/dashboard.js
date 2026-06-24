let currentPromptId = null;
let stats = { total: 0, blocked: 0, poisoned: 0, squats: 0 };
let logCurrentPage = 1;
const logPageLimit = 20;
let logSearchQuery = "";
let logTypeFilter = "";
let settings = {
	mode: 'strict',
	honeypot: true,
	registryAgeCheck: true,
	typosquatCheck: true,
	tarballScan: true,
	pypiScan: true,
	entropyScan: true,
	astScan: true,
	yaraActive: true,
	lockfileActive: false,
	lockfileMode: 'prompt',
	lockfilePaths: '',
	webUIEnabled: true,
	customDomainWhitelist: [],
	customDomainBlacklist: [],
	customPackageWhitelist: [],
	customPackageBlacklist: [],
	customNpmRegistries: [],
	customPypiRegistries: [],
	privateScopes: [],
	promptTimeout: 45,
	killInstallerOnThreat: true,
	threatIntelActive: true,
	localFeedSyncActive: true,
	cloudflareDNSActive: true,
	urlhausLiveActive: true,
	subprocessInterceptionActive: true,
	sensitiveFileAccessActive: true,
	sensitiveFileAccessAction: 'block',
	httpsInspectionActive: false,
	runOnStartup: false
};

// SVG icons for empty state
const emptyStateIcon = `<svg fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h3.75M9 15h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-.621-.504-1.125-1.125-1.125H9.75M8.25 21h8.25A2.25 2.25 0 0018.75 18.75V5.25A2.25 2.25 0 0016.5 3H8.25A2.25 2.25 0 006 5.25v13.5A2.25 2.25 0 008.25 21z" /></svg>`;
const trashIcon = `<svg fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" /></svg>`;

function switchTab(tab) {
	// Close any open custom dropdowns to prevent orphaned menus on body
	document.querySelectorAll('.custom-dropdown').forEach(d => {
		if (d.classList.contains('open')) {
			closeDropdown(d);
		}
	});

	const prevBtn = document.querySelector('.nav-item.active');
	const nextBtn = document.getElementById('tab-btn-' + tab);
	
	const prevActive = document.querySelector('.tab-content.active');
	const nextActive = document.getElementById('tab-' + tab);
	
	if (prevBtn) prevBtn.classList.remove('active');
	if (nextBtn) nextBtn.classList.add('active');

	const titles = {
		'live': 'Live Threat Feed',
		'lists': 'Custom Protection Lists',
		'settings': 'Core Engine Settings'
	};
	const titleEl = document.getElementById('page-title');
	if (titleEl && titles[tab]) {
		titleEl.innerText = titles[tab];
	}

	if (prevActive && prevActive !== nextActive) {
		prevActive.style.opacity = '0';
		prevActive.style.transform = 'translateY(8px)';
		setTimeout(() => {
			prevActive.classList.remove('active');
			nextActive.classList.add('active');
			nextActive.offsetHeight; // force reflow
			nextActive.style.opacity = '1';
			nextActive.style.transform = 'translateY(0)';
		}, 150);
	} else if (!prevActive) {
		nextActive.classList.add('active');
		nextActive.offsetHeight;
		nextActive.style.opacity = '1';
		nextActive.style.transform = 'translateY(0)';
	}
}

function connectSSE() {
	const source = new EventSource("/stream");
	
	source.onmessage = function(event) {
		const data = JSON.parse(event.data);
		
		if (data.type === "event") {
			addLog(data.payload);
		} else if (data.type === "prompt") {
			showPrompt(data.payload);
		} else if (data.type === "prompt_resolved") {
			if (data.payload === currentPromptId) {
				closeModal();
			}
			setTimeout(fetchSettings, 300);
		}
	};

	source.onerror = function() {
		console.warn("SSE connection closed. Reconnecting in 3 seconds...");
		source.close();
		setTimeout(connectSSE, 3000);
	};
}

function fetchSettings() {
	fetch('/api/settings')
		.then(res => res.json())
		.then(data => {
			settings = data;
			
			// Normalize arrays to avoid null crashes
			if (!settings.customDomainWhitelist) settings.customDomainWhitelist = [];
			if (!settings.customDomainBlacklist) settings.customDomainBlacklist = [];
			if (!settings.customPackageWhitelist) settings.customPackageWhitelist = [];
			if (!settings.customPackageBlacklist) settings.customPackageBlacklist = [];
			if (!settings.customNpmRegistries) settings.customNpmRegistries = [];
			if (!settings.customPypiRegistries) settings.customPypiRegistries = [];
			if (!settings.privateScopes) settings.privateScopes = [];

			// Populate UI toggles
			document.getElementById('honeypot-switch').checked = settings.honeypot;
			document.getElementById('registry-age-switch').checked = settings.registryAgeCheck;
			document.getElementById('typosquat-switch').checked = settings.typosquatCheck;
			document.getElementById('tarball-scan-switch').checked = settings.tarballScan;
			document.getElementById('pypi-scan-switch').checked = settings.pypiScan;
			document.getElementById('entropy-scan-switch').checked = settings.entropyScan;
			document.getElementById('ast-scan-switch').checked = settings.astScan;
			document.getElementById('yara-switch').checked = settings.yaraActive;
			document.getElementById('lockfile-switch').checked = settings.lockfileActive;
			document.getElementById('webui-switch').checked = settings.webUIEnabled;
			document.getElementById('startup-switch').checked = settings.runOnStartup;
			document.getElementById('lockfile-mode-select').value = settings.lockfileMode;
			document.getElementById('lockfile-paths-input').value = settings.lockfilePaths;
			document.getElementById('confusion-switch').checked = settings.dependencyConfusionActive;
			document.getElementById('deception-switch').checked = settings.sandboxSpoofing;
			document.getElementById('evasion-action-select').value = settings.sandboxEvasionAction;
			document.getElementById('prompt-timeout-input').value = settings.promptTimeout || 45;
			document.getElementById('kill-threat-switch').checked = settings.killInstallerOnThreat;
			document.getElementById('kill-static-threat-switch').checked = settings.killInstallerOnStaticThreat;
			document.getElementById('auto-cleanup-switch').checked = settings.autoCleanupOnThreat;
			
			// Threat Intelligence Binds
			document.getElementById('threat-intel-switch').checked = settings.threatIntelActive;
			document.getElementById('feed-sync-switch').checked = settings.localFeedSyncActive;
			document.getElementById('cloudflare-dns-switch').checked = settings.cloudflareDNSActive;
			document.getElementById('urlhaus-live-switch').checked = settings.urlhausLiveActive;
			document.getElementById('threat-intel-settings-panel').classList.toggle('visible', settings.threatIntelActive);

			// New Defense Binds
			document.getElementById('subprocess-guard-switch').checked = settings.subprocessInterceptionActive;
			document.getElementById('subprocess-strictness-select').value = settings.subprocessNetworkStrictness;
			document.getElementById('subprocess-guard-panel').classList.toggle('visible', settings.subprocessInterceptionActive);
			document.getElementById('anti-evasion-switch').checked = settings.antiEvasionActive;
			document.getElementById('sensitive-files-switch').checked = settings.sensitiveFileAccessActive;
			document.getElementById('sensitive-files-action-select').value = settings.sensitiveFileAccessAction;
			document.getElementById('sensitive-files-panel').classList.toggle('visible', settings.sensitiveFileAccessActive);

			// Script Sanitizer Binds
			document.getElementById('strip-scripts-mode-select').value = settings.stripLifecycleScripts || 'threats_only';
			document.getElementById('strip-scripts-targets-input').value = (settings.stripLifecycleTargets || []).join(', ');
			document.getElementById('strip-scripts-threats-input').value = (settings.stripLifecycleTriggerThreats || []).join(', ');
			document.getElementById('strip-scripts-exemptions-input').value = (settings.stripLifecycleExemptions || []).join(', ');
			updateStripScriptsUI();

			document.getElementById('https-inspection-switch').checked = settings.httpsInspectionActive;
			fetchCertStatus();

			document.getElementById('lockfile-settings-panel').classList.toggle('visible', settings.lockfileActive);
			updateModeUI();
			renderAllLists();
			syncCustomDropdowns();
		});
}

function setMode(newMode) {
	settings.mode = newMode;
	updateModeUI();
	saveSettings();
}

function updateModeUI() {
	document.querySelectorAll('.mode-btn').forEach(btn => btn.classList.remove('active'));
	const activeBtn = document.getElementById('mode-' + settings.mode);
	if (activeBtn) activeBtn.classList.add('active');
}

function toggleHoneypot(checked) {
	settings.honeypot = checked;
	saveSettings();
}

function toggleRegistryAge(checked) {
	settings.registryAgeCheck = checked;
	saveSettings();
}

function toggleTyposquat(checked) {
	settings.typosquatCheck = checked;
	saveSettings();
}

function toggleTarballScan(checked) {
	settings.tarballScan = checked;
	saveSettings();
}

function togglePypiScan(checked) {
	settings.pypiScan = checked;
	saveSettings();
}

function toggleEntropyScan(checked) {
	settings.entropyScan = checked;
	saveSettings();
}

function toggleASTScan(checked) {
	settings.astScan = checked;
	saveSettings();
}

function toggleYara(checked) {
	settings.yaraActive = checked;
	saveSettings();
}

function toggleWebUI(checked) {
	settings.webUIEnabled = checked;
	saveSettings();
}

function toggleRunOnStartup(checked) {
	settings.runOnStartup = checked;
	saveSettings();
}

function toggleDependencyConfusion(checked) {
	settings.dependencyConfusionActive = checked;
	saveSettings();
}

function toggleSandboxSpoofing(checked) {
	settings.sandboxSpoofing = checked;
	saveSettings();
}

function changeSandboxEvasionAction(val) {
	settings.sandboxEvasionAction = val;
	saveSettings();
}

function toggleLockfile(checked) {
	settings.lockfileActive = checked;
	document.getElementById('lockfile-settings-panel').classList.toggle('visible', checked);
	saveSettings();
}

function changeLockfileMode(val) {
	settings.lockfileMode = val;
	saveSettings();
}

function updateLockfilePaths(val) {
	settings.lockfilePaths = val;
	saveSettings();
}

function changePromptTimeout(val) {
	let num = parseInt(val, 10);
	if (isNaN(num) || num < 5) num = 5;
	if (num > 300) num = 300;
	settings.promptTimeout = num;
	saveSettings();
}

function toggleKillInstaller(checked) {
	settings.killInstallerOnThreat = checked;
	saveSettings();
}

function toggleKillStaticInstaller(checked) {
	settings.killInstallerOnStaticThreat = checked;
	saveSettings();
}

function toggleAutoCleanup(checked) {
	settings.autoCleanupOnThreat = checked;
	saveSettings();
}

function toggleThreatIntel(checked) {
	settings.threatIntelActive = checked;
	document.getElementById('threat-intel-settings-panel').classList.toggle('visible', checked);
	saveSettings();
}

function toggleFeedSync(checked) {
	settings.localFeedSyncActive = checked;
	saveSettings();
}

function toggleCloudflareDNS(checked) {
	settings.cloudflareDNSActive = checked;
	saveSettings();
}

function toggleURLhausLive(checked) {
	settings.urlhausLiveActive = checked;
	saveSettings();
}

function toggleSubprocessGuard(checked) {
	settings.subprocessInterceptionActive = checked;
	document.getElementById('subprocess-guard-panel').classList.toggle('visible', checked);
	saveSettings();
}

function changeSubprocessStrictness(val) {
	settings.subprocessNetworkStrictness = val;
	saveSettings();
}

function toggleAntiEvasion(checked) {
	settings.antiEvasionActive = checked;
	saveSettings();
}

function toggleSensitiveFiles(checked) {
	settings.sensitiveFileAccessActive = checked;
	document.getElementById('sensitive-files-panel').classList.toggle('visible', checked);
	saveSettings();
}

function changeSensitiveFilesAction(val) {
	settings.sensitiveFileAccessAction = val;
	saveSettings();
}

function updateStripScriptsUI() {
	const mode = settings.stripLifecycleScripts || 'threats_only';
	const detailsPanel = document.getElementById('strip-scripts-details-panel');
	const threatsField = document.getElementById('strip-scripts-threats-field');
	
	if (mode === 'never') {
		detailsPanel.style.display = 'none';
	} else {
		detailsPanel.style.display = 'block';
		if (mode === 'threats_only') {
			threatsField.style.display = 'block';
		} else {
			threatsField.style.display = 'none';
		}
	}
}

function changeStripScriptsMode(val) {
	settings.stripLifecycleScripts = val;
	updateStripScriptsUI();
	saveSettings();
}

function updateStripScriptsTargets(val) {
	settings.stripLifecycleTargets = val.split(',').map(s => s.trim()).filter(s => s !== '');
	saveSettings();
}

function updateStripScriptsThreats(val) {
	settings.stripLifecycleTriggerThreats = val.split(',').map(s => s.trim()).filter(s => s !== '');
	saveSettings();
}

function updateStripScriptsExemptions(val) {
	settings.stripLifecycleExemptions = val.split(',').map(s => s.trim()).filter(s => s !== '');
	saveSettings();
}

function saveSettings() {
	fetch('/api/settings', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(settings)
	}).then(() => {
		fetchCertStatus();
	});
}

let defaults = {
	defaultDomainWhitelist: [],
	popularPackages: [],
	secretPatterns: []
};

/* === Custom Lists Code === */
function renderList(listKey, containerId) {
	const container = document.getElementById(containerId);
	container.innerHTML = '';
	const items = settings[listKey] || [];

	let listHtml = '';
	let count = 0;

	// Inject default whitelisted domains first
	if (listKey === 'customDomainWhitelist') {
		const sysItems = defaults.defaultDomainWhitelist || [];
		count += sysItems.length;
		sysItems.forEach(item => {
			listHtml += `
				<div class="list-item" style="opacity: 0.8;">
					<span class="list-item-text" style="color: var(--text-muted);">${escapeHtml(item)}</span>
					<span class="badge-sys">SYSTEM</span>
					<div class="system-icon" title="System Default (Locked)">
						<svg fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
						</svg>
					</div>
				</div>
			`;
		});
	}

	count += items.length;

	// Update rule count badge in the card title
	const countId = containerId.replace('-container', '-count');
	const countEl = document.getElementById(countId);
	if (countEl) {
		countEl.innerText = `${count} Active`;
	}

	if (count === 0) {
		container.innerHTML = `
			<div class="list-empty-state">
				${emptyStateIcon}
				<div>No active entries. Add one above.</div>
			</div>
		`;
		return;
	}

	container.innerHTML = listHtml;

	items.forEach((item, index) => {
		const div = document.createElement('div');
		div.className = 'list-item';
		div.innerHTML = `
			<span class="list-item-text">${escapeHtml(item)}</span>
			<button class="list-item-delete" onclick="removeListItem('${listKey}', ${index}, this.parentNode)" title="Delete entry">
				${trashIcon}
			</button>
		`;
		container.appendChild(div);
	});
}

function renderAllLists() {
	renderList('customDomainWhitelist', 'domain-whitelist-container');
	renderList('customDomainBlacklist', 'domain-blacklist-container');
	renderList('customPackageWhitelist', 'package-whitelist-container');
	renderList('customPackageBlacklist', 'package-blacklist-container');
	renderList('customNpmRegistries', 'npm-registries-container');
	renderList('customPypiRegistries', 'pypi-registries-container');
	renderList('privateScopes', 'private-scopes-container');
}

function fetchDefaults() {
	fetch('/api/defaults')
		.then(res => res.json())
		.then(data => {
			defaults = data;
			
			// Monitored secrets
			const secretsList = document.getElementById('secret-sigs-list');
			if (secretsList) {
				secretsList.innerHTML = '';
				const sigs = defaults.secretPatterns || [];
				document.getElementById('secret-sigs-count').innerText = sigs.length;
				sigs.forEach(sig => {
					const span = document.createElement('span');
					span.className = 'pill-tag';
					span.innerText = sig;
					secretsList.appendChild(span);
				});
			}

			// Typosquat watch list
			const popularList = document.getElementById('popular-pkgs-list');
			if (popularList) {
				popularList.innerHTML = '';
				const pkgs = defaults.popularPackages || [];
				document.getElementById('popular-pkgs-count').innerText = pkgs.length;
				pkgs.forEach(pkg => {
					const span = document.createElement('span');
					span.className = 'pill-tag';
					span.innerText = pkg;
					popularList.appendChild(span);
				});
			}

			// Render Whitelist card with default domains
			renderAllLists();
		});
}

function addListItem(listKey, inputId, containerId) {
	const input = document.getElementById(inputId);
	const value = input.value.trim();
	if (!value) return;

	if (!settings[listKey]) {
		settings[listKey] = [];
	}

	// Avoid duplicates
	if (!settings[listKey].includes(value)) {
		settings[listKey].push(value);
		saveSettings();
		renderList(listKey, containerId);
	}

	input.value = '';
}

function removeListItem(listKey, index, element) {
	if (!element) return;
	element.classList.add('deleting');
	
	// Wait for animation out before committing state
	setTimeout(() => {
		if (settings[listKey]) {
			settings[listKey].splice(index, 1);
			saveSettings();
			// Re-render matching containers
			const containerId = getContainerIdForList(listKey);
			renderList(listKey, containerId);
		}
	}, 200);
}

function getContainerIdForList(listKey) {
	switch (listKey) {
		case 'customDomainWhitelist': return 'domain-whitelist-container';
		case 'customDomainBlacklist': return 'domain-blacklist-container';
		case 'customPackageWhitelist': return 'package-whitelist-container';
		case 'customPackageBlacklist': return 'package-blacklist-container';
		case 'customNpmRegistries': return 'npm-registries-container';
		case 'customPypiRegistries': return 'pypi-registries-container';
		case 'privateScopes': return 'private-scopes-container';
	}
	return '';
}

// Bind enter key press to list inputs
function setupListInputBindings() {
	const bindings = [
		{ inputId: 'domain-whitelist-input', btnId: 'domain-whitelist-btn' },
		{ inputId: 'domain-blacklist-input', btnId: 'domain-blacklist-btn' },
		{ inputId: 'package-whitelist-input', btnId: 'package-whitelist-btn' },
		{ inputId: 'package-blacklist-input', btnId: 'package-blacklist-btn' },
		{ inputId: 'npm-registries-input', btnId: 'npm-registries-btn' },
		{ inputId: 'pypi-registries-input', btnId: 'pypi-registries-btn' },
		{ inputId: 'private-scopes-input', btnId: 'private-scopes-btn' }
	];
	bindings.forEach(b => {
		const input = document.getElementById(b.inputId);
		if (input) {
			input.addEventListener('keyup', function(e) {
				if (e.key === 'Enter') {
					document.getElementById(b.btnId).click();
				}
			});
		}
	});
}

function escapeHtml(str) {
	return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function formatLineage(path) {
	if (!path) return '';
	const parts = path.split(/\s*->\s*/);
	return `
		<div class="lineage-container">
			${parts.map((part, index) => {
				const match = part.match(/^([^(]+)(?:\((\d+)\))?$/);
				if (match) {
					const name = match[1].trim();
					const pid = match[2] ? match[2].trim() : '';
					return `
						<div class="lineage-node" style="animation-delay: ${index * 0.05}s;">
							<span class="lineage-name">${escapeHtml(name)}</span>
							${pid ? `<span class="lineage-pid">${escapeHtml(pid)}</span>` : ''}
						</div>
					`;
				}
				return `<div class="lineage-node">${escapeHtml(part)}</div>`;
			}).join('<span class="lineage-arrow">→</span>')}
		</div>
	`;
}

function addLog(evt, prepend = true) {
	const tbody = document.getElementById('logs-body');
	const tr = document.createElement('tr');
	
	if (prepend) {
		stats.total++;
		if (evt.Type === "BLOCKED" || evt.Type === "INSTALLER_KILLED" || evt.Type === "KILLED") {
			stats.blocked++;
		} else if (evt.Type === "EXFIL") {
			stats.poisoned++;
		} else if (evt.Type === "NEW_PKG") {
			stats.squats++;
		}
		updateStatsUI();
	}

	const date = new Date(evt.Time);
	const timeStr = date.toTimeString().split(' ')[0];

	// Parse domain/host for quick whitelisting
	let domain = null;
	if (evt.Message) {
		let match = evt.Message.match(/connection to '([^']+)'/) || evt.Message.match(/connection to ([^\s]+)/) || evt.Message.match(/host: ([^\s]+)/);
		if (match) {
			domain = match[1];
			// Trim port or tailing punctuation
			if (domain.includes(':')) domain = domain.split(':')[0];
			domain = domain.replace(/['"().]/g, '').trim();
		}
	}

	let descHtml = escapeHtml(evt.Message);
	if (evt.Type === "BLOCKED" && domain && domain.includes('.')) {
		descHtml += `
			<button class="log-whitelist-btn" onclick="quickWhitelist('${escapeHtml(domain)}', this)" style="background: var(--color-moss-veil); border: 1px solid var(--color-forest-floor); color: var(--color-botanical-ink); padding: 2px 8px; border-radius: var(--radius-tags); font-size: 10px; font-family: var(--font-fragment-mono); cursor: pointer; margin-left: 8px; outline: none; transition: all 0.2s;">
				Whitelist
			</button>
		`;
	}

	tr.innerHTML = `
		<td class="time-col">${timeStr}</td>
		<td class="action-col"><span class="badge ${evt.Type.toLowerCase()}">${evt.Type}</span></td>
		<td class="desc-col" data-message="${escapeHtml(evt.Message)}">
			<span class="desc-content">${descHtml}</span>
		</td>
		<td class="tree-col" data-path="${escapeHtml(evt.Path)}">
			${formatLineage(evt.Path)}
		</td>
	`;
	
	if (prepend) {
		// Only prepend to visual grid if on page 1 and matches active search/filters
		const matchesType = !logTypeFilter || evt.Type === logTypeFilter;
		const matchesSearch = !logSearchQuery || 
			evt.Message.toLowerCase().includes(logSearchQuery.toLowerCase()) || 
			evt.Path.toLowerCase().includes(logSearchQuery.toLowerCase());

		if (logCurrentPage === 1 && matchesType && matchesSearch) {
			tbody.insertBefore(tr, tbody.firstChild);
			if (tbody.children.length > logPageLimit) {
				tbody.removeChild(tbody.lastChild);
			}
		}
	} else {
		tbody.appendChild(tr);
	}
}

function updateStatsUI() {
	document.getElementById('stat-total').innerText = stats.total;
	document.getElementById('stat-blocked').innerText = stats.blocked;
	document.getElementById('stat-poisoned').innerText = stats.poisoned;
	document.getElementById('stat-squats').innerText = stats.squats;
}

function showPrompt(payload) {
	currentPromptId = payload.id;
	document.getElementById('modal-host').innerText = payload.host;
	document.getElementById('modal-process').innerText = payload.path;
	
	const pkgRow = document.getElementById('modal-package-row');
	const pkgVal = document.getElementById('modal-package');
	if (pkgRow && pkgVal) {
		if (payload.package) {
			pkgVal.innerText = payload.package;
			pkgRow.style.display = 'flex';
		} else {
			pkgRow.style.display = 'none';
		}
	}
	
	const modal = document.getElementById('prompt-modal');
	modal.style.display = 'flex';
	setTimeout(() => modal.classList.add('active'), 10);
}

function submitDecision(decision) {
	if (!currentPromptId) return;
	
	fetch('/api/respond', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ id: currentPromptId, decision })
	});

	closeModal();
}

function closeModal() {
	const modal = document.getElementById('prompt-modal');
	modal.classList.remove('active');
	setTimeout(() => {
		modal.style.display = 'none';
		currentPromptId = null;
	}, 250);
}

let debounceTimer;
function onFilterChange() {
	clearTimeout(debounceTimer);
	debounceTimer = setTimeout(() => {
		logSearchQuery = document.getElementById('log-search-input').value;
		logTypeFilter = document.getElementById('log-type-filter').value;
		logCurrentPage = 1;
		fetchLogs();
	}, 200);
}

function changePage(delta) {
	logCurrentPage += delta;
	fetchLogs();
}

function updatePaginationUI(totalCount) {
	const totalPages = Math.ceil(totalCount / logPageLimit) || 1;
	
	if (logCurrentPage > totalPages) {
		logCurrentPage = totalPages;
	}
	if (logCurrentPage < 1) {
		logCurrentPage = 1;
	}

	document.getElementById('page-indicator').innerText = `${logCurrentPage} / ${totalPages}`;
	document.getElementById('btn-prev-page').disabled = logCurrentPage <= 1;
	document.getElementById('btn-next-page').disabled = logCurrentPage >= totalPages;
}

function fetchLogs() {
	const offset = (logCurrentPage - 1) * logPageLimit;
	const url = `/api/logs?limit=${logPageLimit}&offset=${offset}&search=${encodeURIComponent(logSearchQuery)}&type=${encodeURIComponent(logTypeFilter)}`;

	fetch(url)
		.then(res => res.json())
		.then(data => {
			const tbody = document.getElementById('logs-body');
			tbody.innerHTML = '';
			
			const logs = data.logs || [];
			const total = data.total || 0;
			
			logs.forEach(evt => {
				addLog(evt, false); // append
			});
			
			updatePaginationUI(total);

			if (data.stats) {
				stats = data.stats;
				updateStatsUI();
			}
		})
		.catch(err => console.error("Error fetching logs:", err));
}

function fetchActivePrompt() {
	fetch('/api/prompt')
		.then(res => res.json())
		.then(data => {
			if (data && data.id) {
				showPrompt(data);
			}
		});
}

function triggerFeedSync() {
	const btn = document.getElementById('sync-feeds-btn');
	if (!btn) return;
	const oldText = btn.innerText;
	btn.innerText = 'Syncing...';
	btn.disabled = true;
	btn.style.opacity = '0.7';

	fetch('/api/reputation/sync', {
		method: 'POST'
	})
	.then(res => res.json())
	.then(data => {
		btn.innerText = 'Sync Triggered!';
		btn.style.borderColor = '#10b981';
		btn.style.color = '#34d399';
		btn.style.background = 'rgba(16, 185, 129, 0.2)';
		setTimeout(() => {
			btn.innerText = oldText;
			btn.disabled = false;
			btn.style.opacity = '1';
			btn.style.borderColor = '#3b82f6';
			btn.style.color = '#60a5fa';
			btn.style.background = 'rgba(59, 130, 246, 0.2)';
		}, 3000);
	})
	.catch(err => {
		console.error(err);
		btn.innerText = 'Sync Failed';
		btn.disabled = false;
		btn.style.opacity = '1';
		setTimeout(() => {
			btn.innerText = oldText;
			btn.style.borderColor = '#3b82f6';
			btn.style.color = '#60a5fa';
			btn.style.background = 'rgba(59, 130, 246, 0.2)';
		}, 3000);
	});
}

function quickWhitelist(domain, button) {
	if (button) {
		button.innerText = 'Whitelisting...';
		button.disabled = true;
	}
	fetch('/api/whitelist', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ domain })
	})
	.then(res => res.json())
	.then(data => {
		if (button) {
			button.innerText = 'Whitelisted!';
			button.style.background = 'var(--color-moss-veil)';
			button.style.borderColor = 'var(--color-forest-floor)';
			button.style.color = 'var(--color-botanical-ink)';
		}
		// Refresh settings to show the updated whitelist
		setTimeout(fetchSettings, 300);
	})
	.catch(err => {
		console.error(err);
		if (button) {
			button.innerText = 'Failed';
			button.disabled = false;
		}
	});
}

window.onload = function() {
	initializeCustomDropdowns();
	initializeGlobalTooltip();
	setupTooltipListeners();
	connectSSE();
	fetchSettings();
	fetchDefaults();
	fetchLogs();
	fetchActivePrompt();
	setupListInputBindings();

	// Initial transition for first tab
	setTimeout(() => {
		const activeTab = document.querySelector('.tab-content.active');
		if (activeTab) {
			activeTab.offsetHeight;
			activeTab.style.opacity = '1';
			activeTab.style.transform = 'translateY(0)';
		}
	}, 100);
};

// --- HTTPS Decryption & Root CA API Handlers ---
function fetchCertStatus() {
	fetch('/api/cert/status')
		.then(res => res.json())
		.then(data => {
			const badge = document.getElementById('cert-status-badge');
			const btnTrust = document.getElementById('btn-trust-cert');
			const btnUntrust = document.getElementById('btn-untrust-cert');
			const callout = document.getElementById('nocert-fallback-callout');
			
			if (badge) {
				if (data.trusted) {
					badge.innerText = "Trusted & Active";
					badge.className = "cert-badge cert-trusted";
					if (btnTrust) btnTrust.style.display = 'none';
					if (btnUntrust) btnUntrust.style.display = '';
				} else {
					badge.innerText = "Untrusted / Suspended";
					badge.className = "cert-badge cert-untrusted";
					if (btnTrust) btnTrust.style.display = '';
					if (btnUntrust) btnUntrust.style.display = 'none';
				}
			}

			if (callout) {
				if (data.trusted && settings.httpsInspectionActive) {
					callout.style.display = 'none';
				} else {
					callout.style.display = 'flex';
				}
			}

			// Update Global PATH Install UI status
			const installBadge = document.getElementById('install-global-badge');
			const btnInstall = document.getElementById('btn-install-global');
			if (installBadge) {
				if (data.installedGlobally) {
					installBadge.style.display = 'inline-block';
					if (btnInstall) {
						btnInstall.innerText = "Update Executable";
					}
				} else {
					installBadge.style.display = 'none';
					if (btnInstall) {
						btnInstall.innerText = "Register Globally";
					}
				}
			}
		})
		.catch(err => console.error("Error fetching cert status:", err));
}

function trustCertificate() {
	const btn = document.getElementById('btn-trust-cert');
	if (btn) {
		btn.innerText = "Trusting...";
		btn.disabled = true;
	}
	fetch('/api/cert/trust', { method: 'POST' })
		.then(res => res.json())
		.then(data => {
			if (btn) {
				btn.innerText = "Trust Root CA Certificate";
				btn.disabled = false;
			}
			if (data.success) {
				fetchCertStatus();
				fetchSettings();
			} else {
				alert(data.message);
			}
		})
		.catch(err => {
			if (btn) {
				btn.innerText = "Trust Root CA Certificate";
				btn.disabled = false;
			}
			console.error("Error trusting cert:", err);
		});
}

function untrustCertificate() {
	const btn = document.getElementById('btn-untrust-cert');
	if (btn) {
		btn.innerText = "Removing...";
		btn.disabled = true;
	}
	fetch('/api/cert/untrust', { method: 'POST' })
		.then(res => res.json())
		.then(data => {
			if (btn) {
				btn.innerText = "Remove / Untrust Certificate";
				btn.disabled = false;
			}
			if (data.success) {
				fetchCertStatus();
				fetchSettings();
			} else {
				alert(data.message);
			}
		})
		.catch(err => {
			if (btn) {
				btn.innerText = "Remove / Untrust Certificate";
				btn.disabled = false;
			}
			console.error("Error untrusting cert:", err);
		});
}

function toggleHttpsInspection(checked) {
	settings.httpsInspectionActive = checked;
	saveSettings();
}

function installGlobally() {
	const btn = document.getElementById('btn-install-global');
	if (btn) {
		btn.innerText = "Registering...";
		btn.disabled = true;
	}
	fetch('/api/install', { method: 'POST' })
		.then(res => res.json())
		.then(data => {
			if (btn) {
				btn.innerText = "Register Globally";
				btn.disabled = false;
			}
			alert(data.message);
			fetchCertStatus();
		})
		.catch(err => {
			if (btn) {
				btn.innerText = "Register Globally";
				btn.disabled = false;
			}
			console.error("Error registering globally:", err);
			alert("An error occurred during registration. Check console logs for details.");
		});
}

// Dynamically transform native selects into custom dropdowns
function initializeCustomDropdowns() {
	const selects = document.querySelectorAll('select');
	selects.forEach(select => {
		// Avoid double initialization
		if (select.nextElementSibling && select.nextElementSibling.classList.contains('custom-dropdown')) {
			return;
		}

		// Hide original select
		select.style.display = 'none';

		// Create custom dropdown container
		const container = document.createElement('div');
		container.className = 'custom-dropdown';
		container.id = 'custom-dropdown-' + select.id;

		// Create trigger button
		const trigger = document.createElement('div');
		trigger.className = 'custom-dropdown-trigger';
		
		const triggerText = document.createElement('span');
		triggerText.className = 'custom-dropdown-text';
		triggerText.innerText = select.options[select.selectedIndex] ? select.options[select.selectedIndex].text : '';
		
		const arrow = document.createElement('span');
		arrow.className = 'custom-dropdown-arrow';
		arrow.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12"><polyline points="6 9 12 15 18 9"></polyline></svg>`;
		
		trigger.appendChild(triggerText);
		trigger.appendChild(arrow);
		container.appendChild(trigger);

		// Create options menu
		const menu = document.createElement('div');
		menu.className = 'custom-dropdown-menu';
		menu.id = 'menu-custom-dropdown-' + select.id;

		// Populate options
		Array.from(select.options).forEach(opt => {
			const item = document.createElement('div');
			item.className = 'custom-dropdown-item';
			if (opt.selected) item.classList.add('selected');
			item.dataset.value = opt.value;
			item.innerText = opt.text;

			item.addEventListener('click', (e) => {
				e.stopPropagation();
				
				// Deselect previous
				menu.querySelectorAll('.custom-dropdown-item').forEach(i => i.classList.remove('selected'));
				item.classList.add('selected');
				
				// Update trigger text
				triggerText.innerText = opt.text;
				
				// Update native select and trigger its change event
				select.value = opt.value;
				select.dispatchEvent(new Event('change'));
				
				// Close menu
				closeDropdown(container);
			});

			menu.appendChild(item);
		});

		container.appendChild(menu);

		// Toggle menu on trigger click
		trigger.addEventListener('click', (e) => {
			e.stopPropagation();
			const isOpen = container.classList.contains('open');
			
			// Close all other custom dropdowns
			document.querySelectorAll('.custom-dropdown').forEach(d => {
				if (d !== container && d.classList.contains('open')) {
					closeDropdown(d);
				}
			});
			
			if (isOpen) {
				closeDropdown(container);
			} else {
				openDropdown(container, trigger, menu);
			}
		});

		// Insert container after the original select
		select.parentNode.insertBefore(container, select.nextSibling);
	});
}

function openDropdown(container, trigger, menu) {
	container.classList.add('open');
	document.body.appendChild(menu);
	
	// Position the menu
	const rect = trigger.getBoundingClientRect();
	menu.style.position = 'absolute';
	menu.style.display = 'block';
	menu.style.minWidth = rect.width + 'px';
	
	// Set coordinates
	const scrollX = window.pageXOffset || document.documentElement.scrollLeft;
	const scrollY = window.pageYOffset || document.documentElement.scrollTop;
	
	menu.style.top = (rect.bottom + scrollY + 6) + 'px';
	
	// Align left with the trigger left
	let left = rect.left + scrollX;
	// check if it goes offscreen right
	if (left + rect.width > window.innerWidth - 16) {
		left = rect.right + scrollX - menu.offsetWidth;
	}
	menu.style.left = left + 'px';
	
	// Trigger CSS transitions
	setTimeout(() => {
		menu.style.opacity = '1';
		menu.style.visibility = 'visible';
		menu.style.transform = 'translateY(0) scale(1)';
	}, 10);
}

function closeDropdown(container) {
	container.classList.remove('open');
	const menu = document.getElementById('menu-' + container.id);
	if (!menu) return;
	
	menu.style.opacity = '0';
	menu.style.visibility = 'hidden';
	menu.style.transform = 'translateY(-8px) scale(0.97)';
	
	setTimeout(() => {
		// Only hide and put back if the dropdown container still exists
		if (document.body.contains(menu) && document.getElementById(container.id)) {
			container.appendChild(menu);
			menu.style.display = 'none';
		}
	}, 200);
}

// Synchronize custom dropdown state with the native select value (useful when programmatically updated)
function syncCustomDropdowns() {
	const selects = document.querySelectorAll('select');
	selects.forEach(select => {
		const container = document.getElementById('custom-dropdown-' + select.id);
		if (!container) return;
		
		const triggerText = container.querySelector('.custom-dropdown-text');
		const menu = document.getElementById('menu-custom-dropdown-' + select.id) || container.querySelector('.custom-dropdown-menu');
		if (!menu) return;
		
		const items = menu.querySelectorAll('.custom-dropdown-item');
		
		const selectedOpt = select.options[select.selectedIndex];
		if (selectedOpt && triggerText) {
			triggerText.innerText = selectedOpt.text;
		}
		
		items.forEach(item => {
			if (item.dataset.value === select.value) {
				item.classList.add('selected');
			} else {
				item.classList.remove('selected');
			}
		});
	});
}

// Close dropdowns when clicking outside
document.addEventListener('click', () => {
	document.querySelectorAll('.custom-dropdown').forEach(d => {
		if (d.classList.contains('open')) {
			closeDropdown(d);
		}
	});
});

// Floating Global Tooltip Logic
let tooltipEl = null;
let currentHoveredCell = null;

function initializeGlobalTooltip() {
	tooltipEl = document.createElement('div');
	tooltipEl.className = 'global-tooltip';
	document.body.appendChild(tooltipEl);
}

function showGlobalTooltip(targetElement, content, isHtml = false) {
	if (!tooltipEl) return;
	
	if (isHtml) {
		tooltipEl.innerHTML = content;
	} else {
		tooltipEl.innerText = content;
	}
	
	tooltipEl.style.display = 'block';
	tooltipEl.style.opacity = '0';
	
	// Position calculation
	const rect = targetElement.getBoundingClientRect();
	const tooltipRect = tooltipEl.getBoundingClientRect();
	
	// Position above target element
	// Horizontal centering: left = rect.left + (rect.width - tooltipRect.width)/2
	// Vertically: top = rect.top - tooltipRect.height - 10
	const scrollX = window.pageXOffset || document.documentElement.scrollLeft;
	const scrollY = window.pageYOffset || document.documentElement.scrollTop;
	
	let left = rect.left + scrollX + (rect.width - tooltipRect.width) / 2;
	let top = rect.top + scrollY - tooltipRect.height - 10;
	
	// Check bounds so it doesn't go offscreen horizontally
	if (left < 10) {
		left = 10;
	} else if (left + tooltipRect.width > window.innerWidth - 10) {
		left = window.innerWidth - tooltipRect.width - 10;
	}
	
	// Check if it goes offscreen vertically at the top. If so, place it below target instead
	if (top - scrollY < 10) {
		top = rect.bottom + scrollY + 10;
		tooltipEl.classList.add('position-below');
	} else {
		tooltipEl.classList.remove('position-below');
	}
	
	tooltipEl.style.left = left + 'px';
	tooltipEl.style.top = top + 'px';
	
	// Fade in
	setTimeout(() => {
		tooltipEl.style.opacity = '1';
	}, 20);
}

function hideGlobalTooltip() {
	if (!tooltipEl) return;
	tooltipEl.style.opacity = '0';
	// Wait for transition to finish
	setTimeout(() => {
		if (tooltipEl.style.opacity === '0') {
			tooltipEl.style.display = 'none';
		}
	}, 150);
}

function setupTooltipListeners() {
	const logsBody = document.getElementById('logs-body');
	if (!logsBody) return;
	
	logsBody.addEventListener('mouseover', function(e) {
		const cell = e.target.closest('.desc-col, .tree-col');
		if (!cell) {
			if (currentHoveredCell) {
				currentHoveredCell = null;
				hideGlobalTooltip();
			}
			return;
		}
		
		if (cell === currentHoveredCell) return; // already showing for this cell
		currentHoveredCell = cell;
		
		if (cell.classList.contains('desc-col')) {
			const msg = cell.dataset.message;
			if (msg) {
				showGlobalTooltip(cell, msg, false);
			}
		} else if (cell.classList.contains('tree-col')) {
			const path = cell.dataset.path;
			if (path) {
				// Format the lineage dynamically using the path
				const lineageHtml = formatLineage(path);
				showGlobalTooltip(cell, lineageHtml, true);
			}
		}
	});
	
	logsBody.addEventListener('mouseout', function(e) {
		const related = e.relatedTarget;
		if (currentHoveredCell && (!related || !currentHoveredCell.contains(related))) {
			currentHoveredCell = null;
			hideGlobalTooltip();
		}
	});
}


