/**
 * CVE Vulnerability Scanner - Unified Application
 * 로컬/원격 스캔 및 스캔 히스토리 통합 관리
 */

// ==================== 전역 상태 ====================
const AppState = {
    localFindings: [],
    remoteHosts: [],
    selectedHostId: null,
    selectedHistoryId: null,
    historyFilter: 'all',
    scanJobs: new Map(),
    pollingIntervals: new Map(),
    selectedScans: [],  // 비교용 선택된 스캔 ID들
    currentScanHistory: []  // 현재 호스트의 스캔 히스토리
};

// ==================== 유틸리티 함수 ====================
function showToast(message, type = 'info') {
    const toastId = 'toast-' + Date.now();
    const bgClass = {
        'success': 'bg-success',
        'error': 'bg-danger',
        'warning': 'bg-warning text-dark',
        'info': 'bg-info text-dark'
    }[type] || 'bg-info';

    const html = `
        <div id="${toastId}" class="toast ${bgClass} text-white" role="alert">
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    document.getElementById('toastContainer').insertAdjacentHTML('beforeend', html);
    const toastEl = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastEl, { delay: 3000 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}

function formatDateTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    // UTC로 저장된 시간을 로컬 시간으로 변환
    return date.toLocaleString('ko-KR', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

function formatDuration(startTime, endTime) {
    if (!startTime) return '-';
    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const diffSec = Math.floor((end - start) / 1000);
    if (diffSec < 60) return `${diffSec}초`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}분 ${diffSec % 60}초`;
    return `${Math.floor(diffSec / 3600)}시간 ${Math.floor((diffSec % 3600) / 60)}분`;
}

function getSeverityBadge(cvss) {
    if (cvss >= 9.0) return '<span class="badge bg-danger">Critical</span>';
    if (cvss >= 7.0) return '<span class="badge bg-warning text-dark">High</span>';
    if (cvss >= 4.0) return '<span class="badge bg-info">Medium</span>';
    return '<span class="badge bg-secondary">Low</span>';
}

function getStatusBadge(status) {
    const badges = {
        'pending': '<span class="badge bg-secondary">대기</span>',
        'running': '<span class="badge bg-primary">실행중</span>',
        'completed': '<span class="badge bg-success">완료</span>',
        'failed': '<span class="badge bg-danger">실패</span>'
    };
    return badges[status] || `<span class="badge bg-secondary">${status}</span>`;
}

function getConfidenceBadge(confidence) {
    const level = confidence || 'medium';
    const badges = {
        'high': '<span class="badge bg-success">높음</span>',
        'medium': '<span class="badge bg-warning text-dark">중간</span>',
        'low': '<span class="badge bg-secondary">낮음</span>'
    };
    return badges[level] || badges['medium'];
}

// ==================== API 호출 ====================
async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(endpoint, {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            ...options
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: '요청 실패' }));
            throw new Error(error.detail || '요청 실패');
        }
        return await response.json();
    } catch (error) {
        console.error(`API Error [${endpoint}]:`, error);
        throw error;
    }
}

// ==================== 로컬 스캔 ====================
async function loadLocalSystemInfo() {
    try {
        const data = await apiCall('/api/system-info');
        document.getElementById('localSystemInfo').innerHTML = `
            <div class="row small">
                <div class="col-6"><strong>OS:</strong> ${data.os || '-'}</div>
                <div class="col-6"><strong>버전:</strong> ${data.os_version || '-'}</div>
                <div class="col-6"><strong>커널:</strong> ${data.kernel_version || '-'}</div>
                <div class="col-6"><strong>아키텍처:</strong> ${data.architecture || '-'}</div>
            </div>
        `;
    } catch (error) {
        document.getElementById('localSystemInfo').innerHTML =
            '<div class="text-danger small">시스템 정보 로드 실패</div>';
    }
}

async function runLocalScan() {
    const btn = document.getElementById('localScanBtn');
    const progress = document.getElementById('localScanProgress');
    const progressBar = progress.querySelector('.progress-bar');
    const statusText = document.getElementById('localScanStatus');

    btn.disabled = true;
    progress.style.display = 'block';
    progressBar.style.width = '10%';
    statusText.textContent = '스캔 시작...';

    try {
        // 선택된 카테고리 수집
        const categories = [];
        document.querySelectorAll('.local-category:checked').forEach(cb => {
            if (cb.value !== 'all') categories.push(cb.value);
        });

        const params = new URLSearchParams();
        if (categories.length > 0) params.append('categories', categories.join(','));
        if (document.getElementById('localFilterPatched').checked) params.append('filter_patched', 'true');
        if (document.getElementById('localFilterOld').checked) params.append('filter_old', 'true');

        statusText.textContent = '패키지 수집 중...';
        progressBar.style.width = '30%';

        const result = await apiCall(`/api/scan?${params.toString()}`);

        progressBar.style.width = '100%';
        statusText.textContent = '완료!';

        AppState.localFindings = result.vulnerabilities || [];
        renderLocalFindings();
        updateLocalSummary(result);

        document.getElementById('localExportCsvBtn').disabled = AppState.localFindings.length === 0;
        showToast(`스캔 완료: ${AppState.localFindings.length}개 취약점 발견`, 'success');

    } catch (error) {
        showToast('로컬 스캔 실패: ' + error.message, 'error');
        statusText.textContent = '스캔 실패';
        progressBar.classList.add('bg-danger');
    } finally {
        btn.disabled = false;
        setTimeout(() => {
            progress.style.display = 'none';
            progressBar.style.width = '0%';
            progressBar.classList.remove('bg-danger');
        }, 2000);
    }
}

function updateLocalSummary(result) {
    const vulns = result.vulnerabilities || [];

    let high = 0, medium = 0, low = 0;
    vulns.forEach(v => {
        const cvss = v.cvss || 0;
        if (cvss >= 7) high++;
        else if (cvss >= 4) medium++;
        else low++;
    });

    document.getElementById('localHighRisk').textContent = high;
    document.getElementById('localMediumRisk').textContent = medium;
    document.getElementById('localLowRisk').textContent = low;
    document.getElementById('localTotalCves').textContent = vulns.length;
    document.getElementById('localPackages').textContent = result.total_packages || '-';
}

function renderLocalFindings() {
    const tbody = document.getElementById('localFindingsBody');

    if (AppState.localFindings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">발견된 취약점이 없습니다</td></tr>';
        return;
    }

    const rows = AppState.localFindings.map(v => `
        <tr class="finding-row" onclick="showCveDetail('${v.cve_id}')">
            <td><code class="small">${v.package_name || '-'}</code></td>
            <td><a href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" target="_blank" onclick="event.stopPropagation()">${v.cve_id}</a></td>
            <td>${v.cvss?.toFixed(1) || '-'}</td>
            <td>${getSeverityBadge(v.cvss || 0)}</td>
            <td>${v.epss ? (v.epss * 100).toFixed(2) + '%' : '-'}</td>
            <td>${v.is_kev ? '<span class="badge bg-danger">KEV</span>' : '-'}</td>
        </tr>
    `).join('');

    tbody.innerHTML = rows;
}

// ==================== 원격 스캔 ====================
async function loadRemoteHosts() {
    try {
        const hosts = await apiCall('/api/remote/hosts');
        AppState.remoteHosts = hosts;
        renderHostsList();
    } catch (error) {
        console.error('호스트 로드 실패:', error);
        document.getElementById('remoteHostsList').innerHTML =
            '<div class="text-center text-danger py-3">호스트 로드 실패</div>';
    }
}

function renderHostsList() {
    const container = document.getElementById('remoteHostsList');

    if (AppState.remoteHosts.length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted py-4">
                <i class="bi bi-cloud-slash fs-1 d-block mb-2"></i>
                등록된 호스트가 없습니다
            </div>
        `;
        return;
    }

    const items = AppState.remoteHosts.map(host => {
        const isSelected = host.id === AppState.selectedHostId;
        const statusClass = host.is_allowed ? 'text-success' : 'text-secondary';
        const statusIcon = host.is_allowed ? 'bi-check-circle-fill' : 'bi-x-circle';

        return `
            <div class="list-group-item list-group-item-action host-item ${isSelected ? 'active' : ''}" 
                 data-host-id="${host.id}">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1" style="cursor: pointer;" onclick="selectHost(${host.id})">
                        <div class="d-flex align-items-center">
                            <i class="bi ${statusIcon} ${statusClass} me-2"></i>
                            <strong>${host.hostname}</strong>
                        </div>
                        <small class="text-muted">${host.ip_address}:${host.ssh_port || 22}</small>
                    </div>
                    <div class="d-flex gap-1">
                        <button class="btn btn-sm btn-outline-primary scan-btn" 
                                onclick="event.stopPropagation(); startRemoteScan(${host.id})"
                                ${!host.is_allowed ? 'disabled title="스캔 비허용"' : ''}>
                            <i class="bi bi-play-fill"></i> 스캔
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" 
                                onclick="event.stopPropagation(); showEditHostModal(${host.id})">
                            <i class="bi bi-pencil"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');

    container.innerHTML = items;
}

function selectHost(hostId) {
    AppState.selectedHostId = hostId;

    // UI 업데이트
    document.querySelectorAll('.host-item').forEach(el => {
        el.classList.toggle('active', parseInt(el.dataset.hostId) === hostId);
    });

    const host = AppState.remoteHosts.find(h => h.id === hostId);
    document.getElementById('selectedHostName').textContent = host ? `(${host.hostname})` : '';

    // 스캔 히스토리 버튼 활성화
    document.getElementById('scanHistoryBtn').disabled = false;

    loadHostFindings(hostId);
}

async function loadHostFindings(hostId) {
    const tbody = document.getElementById('remoteFindingsBody');
    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-3"><span class="spinner-border spinner-border-sm"></span> 로딩 중...</td></tr>';

    try {
        const findings = await apiCall(`/api/remote/hosts/${hostId}/findings`);
        renderRemoteFindings(findings);
        document.getElementById('remoteExportCsvBtn').disabled = findings.length === 0;
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger py-3">취약점 로드 실패</td></tr>';
    }
}

function renderRemoteFindings(findings) {
    const tbody = document.getElementById('remoteFindingsBody');

    if (!findings || findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">발견된 취약점이 없습니다</td></tr>';
        return;
    }

    const rows = findings.map(f => `
        <tr class="finding-row" onclick="showCveDetail('${f.cve_id}')">
            <td><code class="small">${f.package_name || '-'}</code></td>
            <td><a href="https://nvd.nist.gov/vuln/detail/${f.cve_id}" target="_blank" onclick="event.stopPropagation()">${f.cve_id}</a></td>
            <td>${f.cvss_score?.toFixed(1) || f.cvss?.toFixed(1) || '-'}</td>
            <td>${getConfidenceBadge(f.data_confidence)}</td>
            <td>${f.epss_score ? (f.epss_score * 100).toFixed(2) + '%' : '-'}</td>
            <td>${f.is_kev ? '<span class="badge bg-danger">KEV</span>' : '-'}</td>
        </tr>
    `).join('');

    tbody.innerHTML = rows;
}

async function startRemoteScan(hostId) {
    const preset = document.querySelector('input[name="scanPreset"]:checked').value;

    try {
        const result = await apiCall('/api/remote/scan', {
            method: 'POST',
            body: JSON.stringify({ host_id: hostId, preset: preset })
        });

        showToast(`스캔 작업 시작됨 (Job #${result.job_id})`, 'success');

        // 작업 상태 폴링 시작
        startJobPolling(result.job_id);
        loadScanJobs();

    } catch (error) {
        showToast('스캔 시작 실패: ' + error.message, 'error');
    }
}

async function loadScanJobs() {
    try {
        const jobs = await apiCall('/api/remote/jobs');
        renderScanJobs(jobs);
    } catch (error) {
        console.error('작업 목록 로드 실패:', error);
    }
}

function renderScanJobs(jobs) {
    const tbody = document.getElementById('remoteJobsBody');

    if (!jobs || jobs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">진행 중인 작업이 없습니다</td></tr>';
        return;
    }

    // 최근 20개만 표시
    const recentJobs = jobs.slice(0, 20);

    const rows = recentJobs.map(job => {
        const host = AppState.remoteHosts.find(h => h.id === job.host_id);
        const hostName = host?.hostname || `Host #${job.host_id}`;
        const progress = job.progress_percent || 0;
        const phase = job.current_phase || '-';
        const duration = formatDuration(job.started_at, job.finished_at);

        return `
            <tr>
                <td>${hostName}</td>
                <td>${getStatusBadge(job.status)}</td>
                <td><small>${phase}</small></td>
                <td>
                    <div class="progress" style="height: 6px; min-width: 60px;">
                        <div class="progress-bar ${job.status === 'failed' ? 'bg-danger' : ''}" 
                             style="width: ${progress}%"></div>
                    </div>
                    <small class="text-muted">${progress}%</small>
                </td>
                <td><small>${formatDateTime(job.started_at)}</small></td>
                <td><small>${duration}</small></td>
            </tr>
        `;
    }).join('');

    tbody.innerHTML = rows;
}

function startJobPolling(jobId) {
    // 기존 폴링이 있으면 제거
    if (AppState.pollingIntervals.has(jobId)) {
        clearInterval(AppState.pollingIntervals.get(jobId));
    }

    const pollFn = async () => {
        try {
            const job = await apiCall(`/api/remote/jobs/${jobId}`);
            AppState.scanJobs.set(jobId, job);
            loadScanJobs();

            if (job.status === 'completed' || job.status === 'failed') {
                clearInterval(AppState.pollingIntervals.get(jobId));
                AppState.pollingIntervals.delete(jobId);

                if (job.status === 'completed') {
                    showToast(`스캔 완료 (Job #${jobId})`, 'success');
                    // 선택된 호스트면 결과 새로고침
                    if (job.host_id === AppState.selectedHostId) {
                        loadHostFindings(job.host_id);
                    }
                } else {
                    showToast(`스캔 실패 (Job #${jobId}): ${job.error_message || '알 수 없는 오류'}`, 'error');
                }
            }
        } catch (error) {
            console.error('작업 상태 확인 실패:', error);
        }
    };

    // 즉시 실행 후 2초마다 폴링
    pollFn();
    const intervalId = setInterval(pollFn, 2000);
    AppState.pollingIntervals.set(jobId, intervalId);
}

// ==================== 호스트 모달 ====================
function showAddHostModal() {
    document.getElementById('hostModalTitle').innerHTML = '<i class="bi bi-plus-circle me-1"></i>호스트 등록';
    document.getElementById('hostForm').reset();
    document.getElementById('hostId').value = '';
    document.getElementById('hostDeleteBtn').style.display = 'none';
    document.getElementById('hostSshPort').value = '22';
    document.getElementById('hostSshUsername').value = 'root';
    document.getElementById('hostIsAllowed').checked = true;
    toggleAuthMethod();

    new bootstrap.Modal(document.getElementById('hostModal')).show();
}

function showEditHostModal(hostId) {
    const host = AppState.remoteHosts.find(h => h.id === hostId);
    if (!host) return;

    document.getElementById('hostModalTitle').innerHTML = '<i class="bi bi-pencil me-1"></i>호스트 편집';
    document.getElementById('hostId').value = host.id;
    document.getElementById('hostHostname').value = host.hostname;
    document.getElementById('hostIpAddress').value = host.ip_address;
    document.getElementById('hostSshPort').value = host.ssh_port || 22;
    document.getElementById('hostSshUsername').value = host.ssh_username || 'root';
    document.getElementById('hostAuthMethod').value = host.ssh_password ? 'password' : 'key';
    document.getElementById('hostSshKeyPath').value = host.ssh_key_path || '';
    document.getElementById('hostSshPassword').value = host.ssh_password || '';
    document.getElementById('hostTags').value = (host.tags || []).join(', ');
    document.getElementById('hostIsAllowed').checked = host.is_allowed !== false;
    document.getElementById('hostDeleteBtn').style.display = 'inline-block';

    toggleAuthMethod();
    new bootstrap.Modal(document.getElementById('hostModal')).show();
}

function toggleAuthMethod() {
    const method = document.getElementById('hostAuthMethod').value;
    document.getElementById('sshKeyGroup').style.display = method === 'key' ? 'block' : 'none';
    document.getElementById('sshPasswordGroup').style.display = method === 'password' ? 'block' : 'none';
}

async function saveHost() {
    const hostId = document.getElementById('hostId').value;
    const authMethod = document.getElementById('hostAuthMethod').value;
    const tagsInput = document.getElementById('hostTags').value;

    const data = {
        hostname: document.getElementById('hostHostname').value,
        ip_address: document.getElementById('hostIpAddress').value,
        ssh_port: parseInt(document.getElementById('hostSshPort').value) || 22,
        ssh_username: document.getElementById('hostSshUsername').value || 'root',
        ssh_key_path: authMethod === 'key' ? document.getElementById('hostSshKeyPath').value : null,
        ssh_password: authMethod === 'password' ? document.getElementById('hostSshPassword').value : null,
        tags: tagsInput ? tagsInput.split(',').map(t => t.trim()).filter(t => t) : [],
        is_allowed: document.getElementById('hostIsAllowed').checked
    };

    try {
        if (hostId) {
            await apiCall(`/api/remote/hosts/${hostId}`, {
                method: 'PUT',
                body: JSON.stringify(data)
            });
            showToast('호스트 업데이트 완료', 'success');
        } else {
            await apiCall('/api/remote/hosts', {
                method: 'POST',
                body: JSON.stringify(data)
            });
            showToast('호스트 등록 완료', 'success');
        }

        bootstrap.Modal.getInstance(document.getElementById('hostModal')).hide();
        loadRemoteHosts();

    } catch (error) {
        showToast('저장 실패: ' + error.message, 'error');
    }
}

async function deleteHost() {
    const hostId = document.getElementById('hostId').value;
    if (!hostId) return;

    if (!confirm('정말 이 호스트를 삭제하시겠습니까?')) return;

    try {
        await apiCall(`/api/remote/hosts/${hostId}`, { method: 'DELETE' });
        showToast('호스트 삭제 완료', 'success');

        bootstrap.Modal.getInstance(document.getElementById('hostModal')).hide();

        if (AppState.selectedHostId === parseInt(hostId)) {
            AppState.selectedHostId = null;
            document.getElementById('selectedHostName').textContent = '';
            document.getElementById('remoteFindingsBody').innerHTML =
                '<tr><td colspan="6" class="text-center text-muted py-4">호스트를 선택하세요</td></tr>';
        }

        loadRemoteHosts();

    } catch (error) {
        showToast('삭제 실패: ' + error.message, 'error');
    }
}

// ==================== 스캔 히스토리 ====================
async function loadScanHistory() {
    const container = document.getElementById('historyList');
    container.innerHTML = '<div class="text-center py-3"><span class="spinner-border spinner-border-sm"></span></div>';

    try {
        // 로컬 스캔 히스토리
        let localHistory = [];
        try {
            localHistory = await apiCall('/api/scan-history');
        } catch (e) {
            console.log('로컬 히스토리 없음');
        }

        // 원격 스캔 히스토리 (완료된 작업들)
        let remoteJobs = [];
        try {
            const jobs = await apiCall('/api/remote/jobs');
            remoteJobs = jobs.filter(j => j.status === 'completed');
        } catch (e) {
            console.log('원격 작업 히스토리 없음');
        }

        // 통합 및 정렬
        const allHistory = [
            ...localHistory.map(h => ({ ...h, type: 'local', sortDate: new Date(h.scan_started || h.scan_date) })),
            ...remoteJobs.map(j => {
                const host = AppState.remoteHosts.find(h => h.id === j.host_id);
                return {
                    ...j,
                    type: 'remote',
                    sortDate: new Date(j.finished_at || j.started_at),
                    hostname: host?.hostname || `Host #${j.host_id}`
                };
            })
        ].sort((a, b) => b.sortDate - a.sortDate);

        renderHistoryList(allHistory);

    } catch (error) {
        container.innerHTML = '<div class="text-center text-danger py-3">히스토리 로드 실패</div>';
    }
}

function renderHistoryList(history) {
    const container = document.getElementById('historyList');
    const filter = AppState.historyFilter;

    const filtered = history.filter(h => {
        if (filter === 'all') return true;
        return h.type === filter;
    });

    if (filtered.length === 0) {
        container.innerHTML = '<div class="text-center text-muted py-4">스캔 기록이 없습니다</div>';
        return;
    }

    const items = filtered.map(h => {
        const typeIcon = h.type === 'local' ? 'bi-pc-display' : 'bi-hdd-network';
        const typeBadge = h.type === 'local'
            ? '<span class="badge bg-primary">로컬</span>'
            : '<span class="badge bg-success">원격</span>';
        const title = h.type === 'local' ? '로컬 스캔' : h.hostname;
        const date = h.type === 'local'
            ? formatDateTime(h.scan_started || h.scan_date)
            : formatDateTime(h.finished_at || h.started_at);
        const vulnCount = h.type === 'local' ? (h.cves_found || h.vulnerability_count || 0) : (h.findings_count || h.cves_found || 0);

        const itemId = h.type === 'local' ? `local-${h.id}` : `remote-${h.id}`;
        const isSelected = AppState.selectedHistoryId === itemId;

        return `
            <div class="list-group-item list-group-item-action ${isSelected ? 'active' : ''}" 
                 data-history-id="${itemId}" onclick="selectHistory('${itemId}')">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <i class="bi ${typeIcon} me-1"></i>
                        <strong>${title}</strong>
                        <span class="ms-2">${typeBadge}</span>
                    </div>
                    <small class="text-muted">${date}</small>
                </div>
                <small class="text-muted">취약점: ${vulnCount}개</small>
            </div>
        `;
    }).join('');

    container.innerHTML = items;

    // 이전에 선택한 항목이 있으면 다시 선택 상태 표시
    if (AppState.selectedHistoryId) {
        const selectedEl = container.querySelector(`[data-history-id="${AppState.selectedHistoryId}"]`);
        if (selectedEl) selectedEl.classList.add('active');
    }
}

async function selectHistory(historyId) {
    AppState.selectedHistoryId = historyId;

    // UI 업데이트
    document.querySelectorAll('#historyList .list-group-item').forEach(el => {
        el.classList.toggle('active', el.dataset.historyId === historyId);
    });

    document.getElementById('deleteHistoryBtn').disabled = false;

    const [type, id] = historyId.split('-');

    if (type === 'local') {
        await loadLocalHistoryDetail(id);
    } else {
        await loadRemoteHistoryDetail(id);
    }
}

async function loadLocalHistoryDetail(historyId) {
    const infoContainer = document.getElementById('historyDetailInfo');
    const tbody = document.getElementById('historyFindingsBody');

    try {
        const history = await apiCall(`/api/scan-history/${historyId}`);

        infoContainer.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <p class="mb-1"><strong>타입:</strong> <span class="badge bg-primary">로컬</span></p>
                    <p class="mb-1"><strong>스캔 일시:</strong> ${formatDateTime(history.scan_started || history.scan_date)}</p>
                </div>
                <div class="col-md-6">
                    <p class="mb-1"><strong>패키지 수:</strong> ${history.packages_found || history.total_packages || '-'}</p>
                    <p class="mb-1"><strong>취약점 수:</strong> ${history.cves_found || history.vulnerability_count || 0}</p>
                </div>
            </div>
        `;

        // 취약점 목록
        const findings = history.vulnerabilities || [];
        if (findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">발견된 취약점이 없습니다</td></tr>';
        } else {
            const rows = findings.map(v => `
                <tr class="finding-row" onclick="showCveDetail('${v.cve_id}')">
                    <td><code class="small">${v.package_name || '-'}</code></td>
                    <td><a href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" target="_blank" onclick="event.stopPropagation()">${v.cve_id}</a></td>
                    <td>${v.cvss?.toFixed(1) || '-'}</td>
                    <td>${getSeverityBadge(v.cvss || 0)}</td>
                    <td>${v.epss ? (v.epss * 100).toFixed(2) + '%' : '-'}</td>
                    <td>${v.is_kev ? '<span class="badge bg-danger">KEV</span>' : '-'}</td>
                </tr>
            `).join('');
            tbody.innerHTML = rows;
        }

        document.getElementById('historyExportCsvBtn').disabled = findings.length === 0;

    } catch (error) {
        infoContainer.innerHTML = '<div class="text-danger">상세 정보 로드 실패</div>';
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">취약점 로드 실패</td></tr>';
    }
}

async function loadRemoteHistoryDetail(jobId) {
    const infoContainer = document.getElementById('historyDetailInfo');
    const tbody = document.getElementById('historyFindingsBody');

    try {
        const job = await apiCall(`/api/remote/jobs/${jobId}`);
        const host = AppState.remoteHosts.find(h => h.id === job.host_id);

        infoContainer.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <p class="mb-1"><strong>타입:</strong> <span class="badge bg-success">원격</span></p>
                    <p class="mb-1"><strong>호스트:</strong> ${host?.hostname || 'Host #' + job.host_id}</p>
                    <p class="mb-1"><strong>IP:</strong> ${host?.ip_address || '-'}</p>
                </div>
                <div class="col-md-6">
                    <p class="mb-1"><strong>프리셋:</strong> ${job.preset || '-'}</p>
                    <p class="mb-1"><strong>시작:</strong> ${formatDateTime(job.started_at)}</p>
                    <p class="mb-1"><strong>완료:</strong> ${formatDateTime(job.finished_at)}</p>
                    <p class="mb-1"><strong>소요:</strong> ${formatDuration(job.started_at, job.finished_at)}</p>
                </div>
            </div>
        `;

        // 해당 호스트의 취약점 목록
        if (job.host_id) {
            const findings = await apiCall(`/api/remote/hosts/${job.host_id}/findings`);

            if (!findings || findings.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">발견된 취약점이 없습니다</td></tr>';
                document.getElementById('historyExportCsvBtn').disabled = true;
            } else {
                const rows = findings.map(f => `
                    <tr class="finding-row" onclick="showCveDetail('${f.cve_id}')">
                        <td><code class="small">${f.package_name || '-'}</code></td>
                        <td><a href="https://nvd.nist.gov/vuln/detail/${f.cve_id}" target="_blank" onclick="event.stopPropagation()">${f.cve_id}</a></td>
                        <td>${f.cvss_score?.toFixed(1) || '-'}</td>
                        <td>${getSeverityBadge(f.cvss_score || 0)}</td>
                        <td>${f.epss_score ? (f.epss_score * 100).toFixed(2) + '%' : '-'}</td>
                        <td>${f.is_kev ? '<span class="badge bg-danger">KEV</span>' : '-'}</td>
                    </tr>
                `).join('');
                tbody.innerHTML = rows;
                document.getElementById('historyExportCsvBtn').disabled = false;
            }
        }

    } catch (error) {
        infoContainer.innerHTML = '<div class="text-danger">상세 정보 로드 실패</div>';
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">취약점 로드 실패</td></tr>';
    }
}

async function deleteHistory() {
    if (!AppState.selectedHistoryId) return;
    if (!confirm('이 스캔 기록을 삭제하시겠습니까?')) return;

    const [type, id] = AppState.selectedHistoryId.split('-');

    try {
        if (type === 'local') {
            await apiCall(`/api/scan-history/${id}`, { method: 'DELETE' });
        } else {
            await apiCall(`/api/remote/jobs/${id}`, { method: 'DELETE' });
        }

        showToast('스캔 기록 삭제 완료', 'success');
        AppState.selectedHistoryId = null;
        document.getElementById('deleteHistoryBtn').disabled = true;
        document.getElementById('historyDetailInfo').innerHTML = '<div class="text-center text-muted py-3">히스토리를 선택하세요</div>';
        document.getElementById('historyFindingsBody').innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">히스토리를 선택하면 결과가 표시됩니다</td></tr>';

        loadScanHistory();

    } catch (error) {
        showToast('삭제 실패: ' + error.message, 'error');
    }
}

// ==================== 호스트별 스캔 히스토리 ====================
async function showScanHistory() {
    if (!AppState.selectedHostId) {
        showToast('호스트를 먼저 선택하세요', 'warning');
        return;
    }

    AppState.selectedScans = [];
    updateScanSelectionUI();

    const modal = new bootstrap.Modal(document.getElementById('scanHistoryModal'));
    const tbody = document.getElementById('scanHistoryBody');
    tbody.innerHTML = '<tr><td colspan="7" class="text-center py-3"><span class="spinner-border spinner-border-sm"></span> 로딩 중...</td></tr>';

    modal.show();

    try {
        const result = await apiCall(`/api/remote/hosts/${AppState.selectedHostId}/scan-history`);
        AppState.currentScanHistory = result.scans || [];
        renderScanHistoryTable(AppState.currentScanHistory);
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-3">히스토리 로드 실패</td></tr>';
        showToast('스캔 히스토리 로드 실패: ' + error.message, 'error');
    }
}

function renderScanHistoryTable(scans) {
    const tbody = document.getElementById('scanHistoryBody');

    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">스캔 기록이 없습니다</td></tr>';
        return;
    }

    const rows = scans.map((scan, index) => {
        const isSelected = AppState.selectedScans.includes(scan.id);
        const statusBadge = scan.status === 'completed'
            ? '<span class="badge bg-success">완료</span>'
            : '<span class="badge bg-warning">진행중</span>';
        const isLatest = index === 0;

        return `
            <tr data-scan-id="${scan.id}" class="${isSelected ? 'table-primary' : ''}">
                <td>
                    <input type="checkbox" class="scan-checkbox" value="${scan.id}"
                           ${isSelected ? 'checked' : ''}
                           onchange="toggleScanSelection(${scan.id})">
                </td>
                <td>
                    ${formatDateTime(scan.scan_started)}
                    ${isLatest ? '<span class="badge bg-info ms-1">최신</span>' : ''}
                </td>
                <td>${statusBadge}</td>
                <td>${scan.packages_found || '-'}</td>
                <td><strong>${scan.cves_found || 0}</strong></td>
                <td>
                    ${scan.high_risk_count > 0
                ? '<span class="badge bg-danger">' + scan.high_risk_count + '</span>'
                : '<span class="text-muted">0</span>'}
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewScanDetail(${scan.id})">
                        <i class="bi bi-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteScanHistory(${scan.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    tbody.innerHTML = rows;
}

function toggleScanSelection(scanId) {
    const idx = AppState.selectedScans.indexOf(scanId);
    if (idx >= 0) {
        AppState.selectedScans.splice(idx, 1);
    } else {
        if (AppState.selectedScans.length >= 2) {
            // 2개 이상 선택 시 가장 오래된 것 제거
            AppState.selectedScans.shift();
        }
        AppState.selectedScans.push(scanId);
    }

    updateScanSelectionUI();
    renderScanHistoryTable(AppState.currentScanHistory);
}

function updateScanSelectionUI() {
    const count = AppState.selectedScans.length;
    document.getElementById('scanSelectionInfo').textContent = `${count}개 선택됨`;
    document.getElementById('compareScansBtn').disabled = count !== 2;
}

async function compareSelectedScans() {
    if (AppState.selectedScans.length !== 2) {
        showToast('비교할 스캔 2개를 선택하세요', 'warning');
        return;
    }

    const [scan1, scan2] = AppState.selectedScans;
    const hostId = AppState.selectedHostId;

    // 비교 모달 표시
    const historyModal = bootstrap.Modal.getInstance(document.getElementById('scanHistoryModal'));
    historyModal.hide();

    const compareModal = new bootstrap.Modal(document.getElementById('scanCompareModal'));
    document.getElementById('scanCompareContent').innerHTML =
        '<div class="text-center py-4"><span class="spinner-border"></span> 비교 분석 중...</div>';
    compareModal.show();

    try {
        const result = await apiCall(`/api/remote/hosts/${hostId}/compare?scan1=${scan1}&scan2=${scan2}`);
        renderCompareResult(result);
    } catch (error) {
        document.getElementById('scanCompareContent').innerHTML =
            '<div class="text-center text-danger py-4">비교 실패: ' + error.message + '</div>';
        showToast('스캔 비교 실패: ' + error.message, 'error');
    }
}

function renderCompareResult(result) {
    const container = document.getElementById('scanCompareContent');

    const newVulns = result.new || [];
    const resolvedVulns = result.resolved || [];
    const unchangedVulns = result.unchanged || [];

    const html = `
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-secondary text-white">
                        <i class="bi bi-clock-history me-1"></i>이전 스캔
                    </div>
                    <div class="card-body">
                        <p class="mb-1"><strong>ID:</strong> ${result.scan_old?.id || '-'}</p>
                        <p class="mb-1"><strong>일시:</strong> ${formatDateTime(result.scan_old?.scan_started)}</p>
                        <p class="mb-0"><strong>취약점:</strong> ${result.scan_old?.cves_found || 0}개</p>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <i class="bi bi-clock me-1"></i>최신 스캔
                    </div>
                    <div class="card-body">
                        <p class="mb-1"><strong>ID:</strong> ${result.scan_new?.id || '-'}</p>
                        <p class="mb-1"><strong>일시:</strong> ${formatDateTime(result.scan_new?.scan_started)}</p>
                        <p class="mb-0"><strong>취약점:</strong> ${result.scan_new?.cves_found || 0}개</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-4">
                <div class="card border-danger">
                    <div class="card-body text-center">
                        <h3 class="text-danger mb-0">${newVulns.length}</h3>
                        <small class="text-muted">신규 발견</small>
                    </div>
                </div>
            </div>
            <div class="col-4">
                <div class="card border-success">
                    <div class="card-body text-center">
                        <h3 class="text-success mb-0">${resolvedVulns.length}</h3>
                        <small class="text-muted">해결됨</small>
                    </div>
                </div>
            </div>
            <div class="col-4">
                <div class="card border-warning">
                    <div class="card-body text-center">
                        <h3 class="text-warning mb-0">${unchangedVulns.length}</h3>
                        <small class="text-muted">미해결</small>
                    </div>
                </div>
            </div>
        </div>

        <ul class="nav nav-tabs" id="compareTab" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#newVulnsTab">
                    <i class="bi bi-plus-circle text-danger me-1"></i>신규 (${newVulns.length})
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#resolvedVulnsTab">
                    <i class="bi bi-check-circle text-success me-1"></i>해결 (${resolvedVulns.length})
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#unchangedVulnsTab">
                    <i class="bi bi-dash-circle text-warning me-1"></i>미해결 (${unchangedVulns.length})
                </button>
            </li>
        </ul>
        <div class="tab-content border border-top-0 p-3" style="max-height: 400px; overflow-y: auto;">
            <div class="tab-pane fade show active" id="newVulnsTab">
                ${renderVulnList(newVulns, 'danger')}
            </div>
            <div class="tab-pane fade" id="resolvedVulnsTab">
                ${renderVulnList(resolvedVulns, 'success')}
            </div>
            <div class="tab-pane fade" id="unchangedVulnsTab">
                ${renderVulnList(unchangedVulns, 'warning')}
            </div>
        </div>
    `;

    container.innerHTML = html;

    // 비교 결과 저장 (CSV 내보내기용)
    AppState.lastCompareResult = result;
}

function renderVulnList(vulns, colorClass) {
    if (!vulns || vulns.length === 0) {
        return '<div class="text-center text-muted py-3">해당 취약점이 없습니다</div>';
    }

    const rows = vulns.map(v => {
        const cvss = v.cvss_score || v.cvss || 0;
        return `
        <tr onclick="showCveDetail('${v.cve_id}')" style="cursor: pointer;">
            <td><code>${v.package_name || '-'}</code></td>
            <td><a href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" target="_blank" onclick="event.stopPropagation()">${v.cve_id}</a></td>
            <td>${cvss ? cvss.toFixed(1) : '-'}</td>
            <td>${getSeverityBadge(cvss)}</td>
        </tr>
    `}).join('');

    return `
        <table class="table table-sm table-hover mb-0">
            <thead class="table-${colorClass} text-white">
                <tr>
                    <th>패키지</th>
                    <th>CVE ID</th>
                    <th>CVSS</th>
                    <th>심각도</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}

async function viewScanDetail(scanId) {
    try {
        const result = await apiCall(`/api/scan-history/${scanId}`);

        // 간단한 alert로 상세 표시 (또는 별도 모달)
        const vulns = result.vulnerabilities || [];
        let msg = `스캔 ID: ${scanId}\n`;
        msg += `스캔 일시: ${formatDateTime(result.scan_started)}\n`;
        msg += `취약점 수: ${vulns.length}개\n\n`;

        if (vulns.length > 0) {
            msg += `상위 취약점:\n`;
            vulns.slice(0, 5).forEach(v => {
                msg += `- ${v.cve_id} (${v.package_name}) CVSS: ${v.cvss?.toFixed(1) || '-'}\n`;
            });
        }

        alert(msg);
    } catch (error) {
        showToast('상세 조회 실패: ' + error.message, 'error');
    }
}

async function deleteScanHistory(scanId) {
    if (!confirm(`스캔 #${scanId}를 삭제하시겠습니까?\n관련된 모든 취약점 데이터도 삭제됩니다.`)) {
        return;
    }

    try {
        await apiCall(`/api/scan-history/${scanId}`, { method: 'DELETE' });
        showToast('스캔 기록 삭제 완료', 'success');

        // 목록 새로고침
        AppState.selectedScans = AppState.selectedScans.filter(id => id !== scanId);
        updateScanSelectionUI();

        const result = await apiCall(`/api/remote/hosts/${AppState.selectedHostId}/scan-history`);
        AppState.currentScanHistory = result.scans || [];
        renderScanHistoryTable(AppState.currentScanHistory);
    } catch (error) {
        showToast('삭제 실패: ' + error.message, 'error');
    }
}

function exportCompareResult() {
    if (!AppState.lastCompareResult) {
        showToast('비교 결과가 없습니다', 'warning');
        return;
    }

    const result = AppState.lastCompareResult;
    const rows = [];

    const getCvss = (v) => (v.cvss_score || v.cvss || 0).toFixed(1);

    // 신규
    (result.new || []).forEach(v => {
        rows.push([v.package_name, v.cve_id, getCvss(v), '신규']);
    });
    // 해결
    (result.resolved || []).forEach(v => {
        rows.push([v.package_name, v.cve_id, getCvss(v), '해결']);
    });
    // 미해결
    (result.unchanged || []).forEach(v => {
        rows.push([v.package_name, v.cve_id, getCvss(v), '미해결']);
    });

    const headers = ['패키지', 'CVE ID', 'CVSS', '상태'];
    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');

    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `scan_compare_${result.scan_old?.id}_vs_${result.scan_new?.id}.csv`;
    link.click();

    showToast('비교 결과 CSV 다운로드', 'success');
}

// ==================== CVE 상세 모달 ====================
async function showCveDetail(cveId) {
    const modal = new bootstrap.Modal(document.getElementById('cveDetailModal'));
    document.getElementById('cveDetailTitle').textContent = cveId;
    document.getElementById('cveDetailBody').innerHTML = '<div class="text-center py-4"><span class="spinner-border"></span></div>';

    modal.show();

    try {
        const data = await apiCall(`/api/cve/${cveId}`);

        document.getElementById('cveDetailBody').innerHTML = `
            <div class="row mb-3">
                <div class="col-md-6">
                    <h6>기본 정보</h6>
                    <p><strong>CVE ID:</strong> <a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank">${cveId}</a></p>
                    <p><strong>CVSS:</strong> ${data.cvss?.toFixed(1) || '-'} ${getSeverityBadge(data.cvss || 0)}</p>
                    <p><strong>EPSS:</strong> ${data.epss ? (data.epss * 100).toFixed(4) + '%' : '-'}</p>
                    <p><strong>KEV:</strong> ${data.is_kev ? '<span class="badge bg-danger">예</span>' : '아니오'}</p>
                </div>
                <div class="col-md-6">
                    <h6>날짜 정보</h6>
                    <p><strong>발행일:</strong> ${data.published_date || '-'}</p>
                    <p><strong>수정일:</strong> ${data.last_modified || '-'}</p>
                </div>
            </div>
            <div class="mb-3">
                <h6>설명</h6>
                <p class="small">${data.description || '설명 없음'}</p>
            </div>
            ${data.references && data.references.length > 0 ? `
                <div>
                    <h6>참조</h6>
                    <ul class="small">
                        ${data.references.slice(0, 5).map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        `;

    } catch (error) {
        document.getElementById('cveDetailBody').innerHTML = `
            <div class="text-center text-danger py-4">
                CVE 정보를 불러올 수 없습니다<br>
                <a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank" class="btn btn-sm btn-outline-primary mt-2">NVD에서 보기</a>
            </div>
        `;
    }
}

// ==================== CSV 내보내기 ====================
function exportToCsv(findings, filename) {
    if (!findings || findings.length === 0) {
        showToast('내보낼 데이터가 없습니다', 'warning');
        return;
    }

    const headers = ['Package', 'CVE ID', 'CVSS', 'EPSS', 'KEV', 'Description'];
    const rows = findings.map(f => [
        f.package_name || '',
        f.cve_id || '',
        f.cvss || f.cvss_score || '',
        f.epss || f.epss_score || '',
        f.is_kev ? 'Yes' : 'No',
        (f.description || '').replace(/"/g, '""')
    ]);

    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');

    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename || 'vulnerabilities.csv';
    link.click();

    showToast('CSV 파일 다운로드 시작', 'success');
}

// ==================== 이벤트 리스너 초기화 ====================
function initEventListeners() {
    // 로컬 스캔 버튼
    document.getElementById('localScanBtn').addEventListener('click', runLocalScan);

    // 로컬 카테고리 체크박스
    document.getElementById('localCatAll').addEventListener('change', function () {
        const checked = this.checked;
        document.querySelectorAll('.local-category').forEach(cb => {
            if (cb.id !== 'localCatAll') cb.checked = !checked;
        });
    });

    document.querySelectorAll('.local-category:not(#localCatAll)').forEach(cb => {
        cb.addEventListener('change', function () {
            const allChecked = document.querySelectorAll('.local-category:not(#localCatAll):checked').length === 0;
            document.getElementById('localCatAll').checked = allChecked;
        });
    });

    // 호스트 모달 이벤트
    document.getElementById('hostAuthMethod').addEventListener('change', toggleAuthMethod);
    document.getElementById('hostSaveBtn').addEventListener('click', saveHost);
    document.getElementById('hostDeleteBtn').addEventListener('click', deleteHost);

    // 히스토리 필터 버튼
    ['historyFilterAll', 'historyFilterLocal', 'historyFilterRemote'].forEach(id => {
        document.getElementById(id).addEventListener('click', function () {
            document.querySelectorAll('#scanHistory .btn-group .btn').forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');

            const filterMap = { 'historyFilterAll': 'all', 'historyFilterLocal': 'local', 'historyFilterRemote': 'remote' };
            AppState.historyFilter = filterMap[id];
            loadScanHistory();
        });
    });

    // 히스토리 삭제 버튼
    document.getElementById('deleteHistoryBtn').addEventListener('click', deleteHistory);

    // CSV 내보내기 버튼들
    document.getElementById('localExportCsvBtn').addEventListener('click', () => {
        exportToCsv(AppState.localFindings, `local_scan_${new Date().toISOString().slice(0, 10)}.csv`);
    });

    document.getElementById('remoteExportCsvBtn').addEventListener('click', async () => {
        if (AppState.selectedHostId) {
            const findings = await apiCall(`/api/remote/hosts/${AppState.selectedHostId}/findings`);
            const host = AppState.remoteHosts.find(h => h.id === AppState.selectedHostId);
            exportToCsv(findings, `${host?.hostname || 'remote'}_scan_${new Date().toISOString().slice(0, 10)}.csv`);
        }
    });

    document.getElementById('historyExportCsvBtn').addEventListener('click', async () => {
        // 현재 선택된 히스토리의 findings를 export
        const tbody = document.getElementById('historyFindingsBody');
        // 간단하게 현재 보이는 것을 기반으로
        showToast('히스토리 CSV 내보내기', 'info');
    });

    // 탭 변경 이벤트
    document.getElementById('remote-tab').addEventListener('shown.bs.tab', () => {
        loadRemoteHosts();
        loadScanJobs();
    });

    document.getElementById('history-tab').addEventListener('shown.bs.tab', () => {
        loadScanHistory();
    });
}

// ==================== 초기화 ====================
document.addEventListener('DOMContentLoaded', async function () {
    console.log('CVE Scanner App Initializing...');

    initEventListeners();

    // 로컬 스캔 탭 초기화
    await loadLocalSystemInfo();

    // 원격 호스트 미리 로드 (히스토리에서 호스트명 표시용)
    try {
        await loadRemoteHosts();
    } catch (e) {
        console.log('Remote hosts not available');
    }

    console.log('App Initialized');
});

// 전역 함수로 노출
window.showAddHostModal = showAddHostModal;
window.showEditHostModal = showEditHostModal;
window.selectHost = selectHost;
window.startRemoteScan = startRemoteScan;
window.selectHistory = selectHistory;
window.showCveDetail = showCveDetail;
window.showScanHistory = showScanHistory;
window.compareSelectedScans = compareSelectedScans;
window.toggleScanSelection = toggleScanSelection;
window.viewScanDetail = viewScanDetail;
window.deleteScanHistory = deleteScanHistory;
window.exportCompareResult = exportCompareResult;
