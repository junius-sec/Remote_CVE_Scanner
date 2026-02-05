/**
 * Remote CVE Scanner UI
 * 원격 호스트 스캔 전용 UI
 */

// ==================== State ====================
const AppState = {
    hosts: [],
    selectedHostId: null,
    selectedJobId: null,
    selectedScanId: null,  // 현재 선택된 스캔 ID
    currentFindings: [],
    currentSort: { by: 'cvss', order: 'desc' },
    pollingIntervals: new Map(),
    collectorFilter: null,  // null: 전체, 'os', 'kernel', 'local'
    cvssFilters: new Set(),  // CVSS 점수 필터 (중복 선택 가능: HIGH, MED, LOW)
    pocScanning: false,     // PoC 스캔 진행 중 여부
    pocScanProgress: 0      // PoC 스캔 진행률
};

// ==================== Utility Functions ====================
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
    document.querySelector('.toast-container').insertAdjacentHTML('beforeend', html);
    const toastEl = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastEl, { delay: 3000 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}

function formatDateTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    return date.toLocaleString('ko-KR', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

function formatPhase(phase) {
    const phaseMap = {
        'pending': '대기 중',
        'discovery': '호스트 탐지',
        'deepscan': '패키지 수집',
        'snapshot': '스냅샷 저장',
        'cve_analysis': 'CVE 스캔 중',
        'poc_scan': 'PoC 검색 중',
        'process_check': '프로세스 확인',
        'complete': '완료',
        'failed': '실패'
    };
    return phaseMap[phase] || phase || '-';
}

function formatDuration(startTime, endTime) {
    if (!startTime) return '-';
    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const diffSec = Math.floor((end - start) / 1000);
    if (diffSec < 60) return `${diffSec}초`;
    if (diffSec < 3600) {
        const minutes = Math.floor(diffSec / 60);
        const seconds = diffSec % 60;
        return `${minutes}분 ${seconds}초`;
    }
    const hours = Math.floor(diffSec / 3600);
    const minutes = Math.floor((diffSec % 3600) / 60);
    const seconds = diffSec % 60;
    return `${hours}시간 ${minutes}분 ${seconds}초`;
}

function getCvssClass(cvss) {
    if (cvss >= 9.0) return 'badge bg-danger';
    if (cvss >= 7.0) return 'badge bg-warning text-dark';
    if (cvss >= 4.0) return 'badge bg-info';
    return 'badge bg-secondary';
}

function getStatusBadge(status) {
    const badges = {
        'pending': '<span class="badge bg-secondary">대기</span>',
        'running': '<span class="badge bg-primary"><span class="spinner-border spinner-border-sm me-1"></span>실행중</span>',
        'completed': '<span class="badge bg-success">완료</span>',
        'failed': '<span class="badge bg-danger">실패</span>'
    };
    return badges[status] || `<span class="badge bg-secondary">${status}</span>`;
}

function getCollectorBadge(mode) {
    const badges = {
        'pkg': '<span class="badge bg-primary" title="패키지 매니저">PKG</span>',
        'binary': '<span class="badge bg-info" title="바이너리 분석">BIN</span>',
        'kernel': '<span class="badge bg-warning text-dark" title="커널 CVE">KRN</span>',
        'banner': '<span class="badge bg-secondary" title="배너">BNR</span>',
        'local': '<span class="badge bg-success" title="로컬 스캔">LOC</span>',
        'os': '<span class="badge bg-danger" title="OS 패키지 CVE">OS</span>'
    };
    return badges[mode] || '<span class="badge bg-secondary">-</span>';
}

// 수집방식 필터 적용
function setCollectorFilter(mode) {
    AppState.collectorFilter = mode;

    // 버튼 활성화 상태 업데이트
    document.querySelectorAll('.collector-filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.mode === (mode || 'all')) {
            btn.classList.add('active');
        }
    });

    // 현재 선택된 호스트가 있으면 다시 로드
    if (AppState.selectedHostId) {
        if (AppState.selectedScanId) {
            loadHostFindingsByScan(AppState.selectedHostId, AppState.selectedScanId, mode);
        } else {
            loadHostFindings(AppState.selectedHostId, mode);
        }
    }
}

// CVSS 필터 토글 (중복 선택 가능)
function toggleCvssFilter(level) {
    if (AppState.cvssFilters.has(level)) {
        AppState.cvssFilters.delete(level);
    } else {
        AppState.cvssFilters.add(level);
    }

    // 버튼 활성화 상태 업데이트
    document.querySelectorAll('.cvss-filter-btn').forEach(btn => {
        if (btn.dataset.cvss === level) {
            btn.classList.toggle('active', AppState.cvssFilters.has(level));
        }
    });

    // 현재 findings 필터링 및 재렌더링
    renderFindings(AppState.currentFindings);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==================== API Functions ====================
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

// ==================== Host Management ====================
async function loadRemoteHosts() {
    try {
        const hosts = await apiCall('/api/remote/hosts?allowed_only=false');
        AppState.hosts = hosts;
        renderHostsList();
        document.getElementById('hostCount').textContent = hosts.length;
    } catch (error) {
        console.error('호스트 로드 실패:', error);
        showToast('호스트 목록 로드 실패', 'error');
    }
}

function renderHostsList() {
    const container = document.getElementById('remoteHostsList');

    if (!AppState.hosts || AppState.hosts.length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted py-5">
                <i class="bi bi-cloud-slash fs-1 d-block mb-2"></i>
                <p class="small">등록된 호스트가 없습니다</p>
            </div>
        `;
        return;
    }

    container.innerHTML = AppState.hosts.map(host => {
        const isSelected = host.id === AppState.selectedHostId;
        const allowedIcon = host.is_allowed ?
            '<i class="bi bi-check-circle-fill text-success"></i>' :
            '<i class="bi bi-x-circle text-secondary"></i>';

        return `
            <div class="list-group-item list-group-item-action host-item"
                 onclick="selectHost(${host.id})">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <div class="d-flex align-items-center mb-1">
                            ${allowedIcon}
                            <strong class="ms-2">${escapeHtml(host.hostname)}</strong>
                        </div>
                        <div class="small text-muted">
                            <i class="bi bi-hdd me-1"></i>${escapeHtml(host.ip_address)}:${host.ssh_port || 22}
                            ${host.distro_id ? `<span class="badge bg-secondary ms-1">${host.distro_id}</span>` : ''}
                        </div>
                    </div>
                    <div class="d-flex flex-column gap-1">
                        <button class="btn btn-sm ${host.is_allowed ? 'btn-success' : 'btn-secondary'}" 
                                onclick="event.stopPropagation(); startRemoteScan(${host.id})" 
                                ${!host.is_allowed ? 'disabled title="스캔 비허용"' : ''}>
                            <i class="bi bi-play-fill"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" 
                                onclick="event.stopPropagation(); editHost(${host.id})">
                            <i class="bi bi-pencil"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

async function selectHost(hostId) {
    AppState.selectedHostId = hostId;  // 호스트 ID 저장
    AppState.selectedJobId = null;

    renderHostsList();
    await loadHostDetails(hostId);
    await loadHostFindings(hostId);

    // 스캔 옵션 표시
    const scanOptions = document.getElementById('scanOptions');
    if (scanOptions) {
        scanOptions.style.display = 'block';
    }

    // 히스토리 버튼 활성화
    const historyBtn = document.getElementById('scanHistoryBtn');
    if (historyBtn) {
        historyBtn.disabled = false;
    }
}

async function loadHostDetails(hostId) {
    const host = AppState.hosts.find(h => h.id === hostId);
    if (!host) return;

    const infoDiv = document.getElementById('selectedHostInfo');
    const detailsDiv = document.getElementById('selectedHostDetails');

    infoDiv.style.display = 'block';

    // 최신 스냅샷에서 상세 OS 정보 가져오기
    let osDetails = '';
    try {
        const snapshot = await apiCall(`/api/remote/snapshots/${hostId}/latest`);
        osDetails = `
            <div class="mb-2">
                <strong>OS:</strong> ${snapshot.distro_id || host.os_type} ${snapshot.distro_version || ''}
            </div>
            <div class="mb-2">
                <strong>커널:</strong> <code class="small">${snapshot.kernel_version || '-'}</code>
            </div>
            <div class="mb-2">
                <strong>아키텍처:</strong> ${snapshot.arch || '-'}
            </div>
            <div class="mb-2">
                <strong>패키지 관리자:</strong> ${snapshot.pkg_manager || '-'}
            </div>
            <div class="mb-2">
                <strong>BusyBox:</strong> ${snapshot.is_busybox ? '<span class="badge bg-info">Yes</span>' : 'No'}
            </div>
            <div class="mb-2">
                <strong>systemd:</strong> ${snapshot.has_systemd ? '<span class="badge bg-success">Yes</span>' : 'No'}
            </div>
            <div class="mb-2">
                <strong>마지막 스캔:</strong> ${formatDateTime(snapshot.created_at)}
            </div>
            <div>
                <strong>수집 패키지:</strong> ${snapshot.packages_count || 0}개
            </div>
        `;
    } catch (error) {
        osDetails = `
            <div class="mb-2">
                <strong>IP:</strong> ${host.ip_address}
            </div>
            <div class="mb-2">
                <strong>SSH:</strong> ${host.ssh_username}@${host.ip_address}:${host.ssh_port || 22}
            </div>
            <div>
                <small class="text-muted">스캔을 실행하면 상세 정보가 표시됩니다</small>
            </div>
        `;
    }

    detailsDiv.innerHTML = osDetails;
}

async function loadHostFindings(hostId, collectorMode = null) {
    const tbody = document.getElementById('findingsBody');
    tbody.innerHTML = '<tr><td colspan="9" class="text-center py-3"><span class="spinner-border spinner-border-sm"></span> 로딩 중...</td></tr>';

    try {
        let url = `/api/remote/hosts/${hostId}/findings`;
        const params = [];
        if (AppState.selectedScanId) params.push(`scan_id=${AppState.selectedScanId}`);
        if (collectorMode) params.push(`collector_mode=${collectorMode}`);
        if (params.length > 0) url += '?' + params.join('&');

        const findings = await apiCall(url);

        // 기존 PoC 정보를 새로운 findings에 병합
        if (AppState.currentFindings && AppState.currentFindings.length > 0) {
            const pocMap = new Map();
            AppState.currentFindings.forEach(f => {
                if (f.has_exploit) {
                    pocMap.set(f.cve_id, {
                        has_exploit: f.has_exploit,
                        exploit_count: f.exploit_count
                    });
                }
            });

            findings.forEach(f => {
                const pocInfo = pocMap.get(f.cve_id);
                if (pocInfo) {
                    f.has_exploit = pocInfo.has_exploit;
                    f.exploit_count = pocInfo.exploit_count;
                }
            });
        }

        AppState.currentFindings = findings;
        renderFindings(findings);
        updateStats(findings);

        document.getElementById('viewSbomBtn').disabled = false;  // SBOM은 항상 활성화 (호스트 선택시)
        updatePocScanUI();  // PoC 스캔 버튼 상태 업데이트
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="9" class="text-center text-danger py-3">취약점 로드 실패</td></tr>';
        console.error('Findings load error:', error);
    }
}

async function loadHostFindingsByScan(hostId, scanId, collectorMode = null) {
    const tbody = document.getElementById('findingsBody');
    tbody.innerHTML = '<tr><td colspan="9" class="text-center py-3"><span class="spinner-border spinner-border-sm"></span> 로딩 중...</td></tr>';

    try {
        let url = `/api/remote/hosts/${hostId}/findings?scan_id=${scanId}`;
        if (collectorMode) url += `&collector_mode=${collectorMode}`;

        const findings = await apiCall(url);

        // 기존 PoC 정보를 새로운 findings에 병합
        if (AppState.currentFindings && AppState.currentFindings.length > 0) {
            const pocMap = new Map();
            AppState.currentFindings.forEach(f => {
                if (f.has_exploit) {
                    pocMap.set(f.cve_id, {
                        has_exploit: f.has_exploit,
                        exploit_count: f.exploit_count
                    });
                }
            });

            findings.forEach(f => {
                const pocInfo = pocMap.get(f.cve_id);
                if (pocInfo) {
                    f.has_exploit = pocInfo.has_exploit;
                    f.exploit_count = pocInfo.exploit_count;
                }
            });
        }

        AppState.currentFindings = findings;
        AppState.selectedScanId = scanId;
        renderFindings(findings);
        updateStats(findings);

        document.getElementById('viewSbomBtn').disabled = false;
        updatePocScanUI();  // PoC 스캔 버튼 상태 업데이트
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="9" class="text-center text-danger py-3">취약점 로드 실패</td></tr>';
        console.error('Findings load error:', error);
    }
}

// ==================== Scan Jobs ====================
async function startRemoteScan(hostId) {
    const preset = 'deep';
    const startYear = parseInt(document.getElementById('cveYearStart')?.value) || 1999;
    const cveYears = startYear === 1999 ? null : startYear;  // 시작 년도 자체를 전달

    try {
        const result = await apiCall('/api/remote/scan', {
            method: 'POST',
            body: JSON.stringify({
                host_id: hostId,
                preset: preset,
                cve_years: cveYears
            })
        });

        showToast(`스캔 시작됨 (Job #${result.job_id})`, 'success');
        pollJobStatus(result.job_id);

        // 스캔 시작 시 선택 (이전 결과 표시 방지)
        AppState.selectedJobId = result.job_id;
        AppState.selectedHostId = hostId;

        // Job 목록과 호스트 정보만 로드 (결과는 로드 X)
        await loadScanJobs();

        // 0.5초 후 다시 한 번 로드 (빠른 반영)
        setTimeout(loadScanJobs, 500);

        await loadHostDetails(hostId);

        // Findings는 스캔 중 메시지 표시
        const tbody = document.getElementById('findingsBody');
        tbody.innerHTML = '<tr><td colspan="9" class="text-center py-4"><span class="spinner-border spinner-border-sm me-2"></span>스캔 진행 중... (완료되면 결과가 표시됩니다)</td></tr>';

        // 통계도 초기화
        updateStats([]);
    } catch (error) {
        const detail = error.detail || error.message;
        showToast(`호스트 저장 실패: ${detail}`, 'error');
        console.error('Host save error:', error);
    }
}

async function loadScanJobs() {
    try {
        const jobs = await apiCall('/api/remote/jobs?limit=50');
        renderScanJobs(jobs);
    } catch (error) {
        console.error('작업 목록 로드 실패:', error);
    }
}

function renderScanJobs(jobs) {
    const tbody = document.getElementById('remoteJobsBody');

    if (!jobs || jobs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">스캔 작업이 없습니다</td></tr>';
        return;
    }

    tbody.innerHTML = jobs.map(job => {
        const host = AppState.hosts.find(h => h.id === job.host_id);
        const hostname = host?.hostname || `Host #${job.host_id}`;
        const isSelected = job.id === AppState.selectedJobId;
        const progress = job.progress_percent || 0;

        const hasError = job.status === 'failed' && job.error_message;
        const errorPreview = hasError ? job.error_message.substring(0, 50) + '...' : '';

        // 실행 중인 작업은 자동 갱신
        if (job.status === 'running' && !AppState.pollingIntervals.has(job.id)) {
            pollJobStatus(job.id);
        }

        return `
            <tr class="job-row ${isSelected ? 'selected' : ''}" 
                onclick="selectJob(${job.id}, ${job.host_id})"
                oncontextmenu="showJobContextMenu(event, ${job.id}, '${job.status}'); return false;">
                <td>${escapeHtml(hostname)}</td>
                <td>
                    ${getStatusBadge(job.status)}
                    ${hasError ? `<i class="bi bi-exclamation-triangle-fill text-danger ms-1" title="${escapeHtml(errorPreview)}" onclick="event.stopPropagation(); showJobError(${job.id})"></i>` : ''}
                </td>
                <td><small>${formatPhase(job.current_phase)}</small></td>
                <td>
                    <div class="progress" style="height: 6px;">
                        <div class="progress-bar ${job.status === 'failed' ? 'bg-danger' : ''}" 
                             style="width: ${progress}%"></div>
                    </div>
                    <small class="text-muted">${progress}%</small>
                </td>
                <td><small>${formatDateTime(job.started_at)}</small></td>
                <td><small>${formatDuration(job.started_at, job.completed_at)}</small></td>
                <td><small class="text-muted">${job.cves_found || 0} CVEs</small></td>
            </tr>
        `;
    }).join('');
}

async function selectJob(jobId, hostId) {
    AppState.selectedJobId = jobId;
    AppState.selectedHostId = hostId;

    // 해당 job의 scan_id 가져오기
    try {
        const job = await apiCall(`/api/remote/jobs/${jobId}`);
        if (job.scan_id) {
            AppState.selectedScanId = job.scan_id;
            console.log(`[selectJob] Job ${jobId} has scan_id=${job.scan_id}`);
        } else {
            AppState.selectedScanId = null;
            console.log(`[selectJob] Job ${jobId} has no scan_id, will load latest`);
        }
    } catch (e) {
        console.error('Failed to get job details:', e);
        AppState.selectedScanId = null;
    }

    renderScanJobs(await apiCall('/api/remote/jobs?limit=50'));
    await loadHostDetails(hostId);
    await loadHostFindings(hostId);  // selectedScanId가 있으면 해당 스캔 로드
}

function pollJobStatus(jobId) {
    if (AppState.pollingIntervals.has(jobId)) {
        clearInterval(AppState.pollingIntervals.get(jobId));
    }

    const pollFn = async () => {
        try {
            const job = await apiCall(`/api/remote/jobs/${jobId}`);
            loadScanJobs();

            if (job.status === 'completed' || job.status === 'failed') {
                clearInterval(AppState.pollingIntervals.get(jobId));
                AppState.pollingIntervals.delete(jobId);

                if (job.status === 'completed') {
                    showToast(`스캔 완료 (Job #${jobId})`, 'success');
                    // 현재 선택된 job이면 해당 scan_id의 findings 로드
                    if (jobId === AppState.selectedJobId) {
                        console.log(`[pollJobStatus] Loading findings for completed job ${jobId}, scan_id=${job.scan_id}`);
                        if (job.scan_id) {
                            await loadHostFindingsByScan(job.host_id, job.scan_id);
                        } else {
                            console.warn(`[pollJobStatus] No scan_id found, loading latest findings`);
                            await loadHostFindings(job.host_id);
                        }
                    }
                } else if (job.status === 'failed') {
                    const errorMsg = job.error_message ? `<br><small>${job.error_message.substring(0, 100)}</small>` : '';
                    showToast(`스캔 실패 (Job #${jobId})${errorMsg}`, 'error');
                    // 실패 시 빈 결과 표시
                    if (jobId === AppState.selectedJobId) {
                        const tbody = document.getElementById('findingsBody');
                        tbody.innerHTML = '<tr><td colspan="9" class="text-center text-danger py-3">스캔 실패</td></tr>';
                        updateStats([]);
                    }
                }
            }
        } catch (error) {
            console.error('Poll error:', error);
        }
    };

    pollFn();
    const intervalId = setInterval(pollFn, 1000); // 1초마다 갱신 (진행률 표시 개선)
    AppState.pollingIntervals.set(jobId, intervalId);
}

// 스캔 작업 우클릭 메뉴
function showJobContextMenu(event, jobId, status) {
    event.preventDefault();

    // 기존 메뉴 제거
    const existingMenu = document.getElementById('jobContextMenu');
    if (existingMenu) existingMenu.remove();

    const menu = document.createElement('div');
    menu.id = 'jobContextMenu';
    menu.className = 'dropdown-menu show';
    menu.style.position = 'fixed';
    menu.style.left = event.clientX + 'px';
    menu.style.top = event.clientY + 'px';
    menu.style.zIndex = '9999';

    const menuItems = [];

    if (status === 'running') {
        menuItems.push(`<a class="dropdown-item text-warning" href="#" onclick="stopScanJob(${jobId}); return false;"><i class="bi bi-stop-circle me-2"></i>스캔 중지</a>`);
    }

    menuItems.push(`<a class="dropdown-item text-danger" href="#" onclick="deleteScanJob(${jobId}); return false;"><i class="bi bi-trash me-2"></i>삭제</a>`);

    menu.innerHTML = menuItems.join('');
    document.body.appendChild(menu);

    // 외부 클릭 시 메뉴 닫기
    const closeMenu = (e) => {
        if (!menu.contains(e.target)) {
            menu.remove();
            document.removeEventListener('click', closeMenu);
        }
    };
    setTimeout(() => document.addEventListener('click', closeMenu), 100);
}

async function stopScanJob(jobId) {
    if (!confirm('정말 이 스캔 작업을 중지하시겠습니까?')) return;

    try {
        // 폴링 중지
        if (AppState.pollingIntervals.has(jobId)) {
            clearInterval(AppState.pollingIntervals.get(jobId));
            AppState.pollingIntervals.delete(jobId);
        }

        // API 호출 (서버에 중지 요청)
        await apiCall(`/api/remote/jobs/${jobId}/cancel`, { method: 'POST' });
        showToast('스캔 작업이 중지되었습니다', 'success');
        await loadScanJobs();
    } catch (error) {
        showToast('스캔 중지 실패: ' + error.message, 'error');
    }
}

async function deleteScanJob(jobId) {
    if (!confirm('정말 이 스캔 작업을 삭제하시겠습니까?')) return;

    try {
        // 컨텍스트 메뉴 닫기
        const menu = document.getElementById('jobContextMenu');
        if (menu) menu.remove();

        // 폴링 중지
        if (AppState.pollingIntervals.has(jobId)) {
            clearInterval(AppState.pollingIntervals.get(jobId));
            AppState.pollingIntervals.delete(jobId);
        }

        await apiCall(`/api/remote/jobs/${jobId}`, { method: 'DELETE' });
        showToast('스캔 작업이 삭제되었습니다', 'success');

        // 삭제된 작업이 선택되어 있었다면 선택 해제
        if (AppState.selectedJobId === jobId) {
            AppState.selectedJobId = null;
        }

        await loadScanJobs();
    } catch (error) {
        showToast('스캔 작업 삭제 실패: ' + error.message, 'error');
    }
}

// ==================== Findings Display ====================
function renderFindings(findings) {
    const tbody = document.getElementById('findingsBody');

    if (!findings || findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-5"><i class="bi bi-check-circle fs-1 d-block mb-2"></i><p>발견된 취약점이 없습니다</p></td></tr>';
        document.getElementById('dashboardStats').style.display = 'none';
        document.getElementById('findingsCount').textContent = '0';
        return;
    }

    // CVSS 필터링 적용 (HIGH: 7.0~10.0, MED: 4.0~6.9, LOW: 0.1~3.9)
    const totalCount = findings.length;
    let filteredFindings = findings;

    if (AppState.cvssFilters.size > 0) {
        filteredFindings = findings.filter(f => {
            const score = f.cvss_score;
            if (!score) return false;

            const levels = [];
            if (score >= 7.0) levels.push('HIGH');
            else if (score >= 4.0) levels.push('MED');
            else levels.push('LOW');

            return levels.some(level => AppState.cvssFilters.has(level));
        });
    }

    const filteredCount = filteredFindings.length;

    if (filteredFindings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-5"><i class="bi bi-filter fs-1 d-block mb-2"></i><p>필터 조건에 맞는 취약점이 없습니다</p></td></tr>';
        document.getElementById('findingsCount').textContent = totalCount === filteredCount ? `${totalCount}` : `${totalCount} (${filteredCount})`;
        return;
    }

    // 정렬
    sortFindings(filteredFindings);

    tbody.innerHTML = filteredFindings.map(f => {
        // 시스템 패키지인 경우 특별 표시
        const isSystemPkg = f.package_name && f.package_name.startsWith('__');
        const displayName = isSystemPkg ?
            (f.package_name === '__OS__' ? 'OS' :
                f.package_name === '__KERNEL__' ? 'Linux Kernel' : f.package_name) :
            escapeHtml(f.package_name || 'Unknown');
        const displayVersion = isSystemPkg ?
            `<small class="text-primary">${escapeHtml(f.package_version || '-')}</small>` :
            `<small class="text-muted">${escapeHtml(f.package_version || '-')}</small>`;

        // PoC 버튼 (있으면 돋보기 + 숫자, 없으면 돋보기만)
        const pocBtn = f.has_exploit ?
            `<button class="btn btn-sm btn-outline-danger py-0 px-2" onclick="event.stopPropagation(); showPocModal('${f.cve_id}')" title="PoC ${f.exploit_count || ''}개">
                <i class="bi bi-search"></i> ${f.exploit_count || ''}
            </button>` :
            `<button class="btn btn-sm btn-outline-secondary py-0 px-2" onclick="event.stopPropagation(); searchPoc('${f.cve_id}')" title="PoC 검색">
                <i class="bi bi-search"></i>
            </button>`;

        return `
        <tr class="finding-row ${isSystemPkg ? 'table-warning' : ''}" onclick="showCveDetail('${f.cve_id}')">
            <td>
                <div class="fw-medium">${displayName}</div>
            </td>
            <td>${displayVersion}</td>
            <td>
                <a href="https://nvd.nist.gov/vuln/detail/${f.cve_id}" target="_blank" 
                   onclick="event.stopPropagation()" class="text-decoration-none">
                    ${f.cve_id}
                </a>
            </td>
            <td><span class="${getCvssClass(f.cvss_score)}">${f.cvss_score?.toFixed(1) || 'N/A'}</span></td>
            <td>${f.epss_score ? (f.epss_score * 100).toFixed(2) + '%' : '-'}</td>
            <td>${f.is_kev ? '<span class="badge bg-danger" title="CISA KEV">KEV</span>' : '-'}</td>
            <td>${pocBtn}</td>
            <td>${getCollectorBadge(f.collector_mode)}</td>
            <td><small>${f.pkg_is_running === true ? '<span class="badge bg-success">실행</span>' : (f.pkg_last_used ? `<span class="text-muted">${f.pkg_last_used}</span>` : '-')}</small></td>
        </tr>
        `;
    }).join('');

    // 개수 표시: 전체(필터)
    document.getElementById('findingsCount').textContent = totalCount === filteredCount ? `${totalCount}` : `${totalCount} (${filteredCount})`;
}

// CVSS 점수로 Severity 판별
function getCvssServerity(score) {
    if (!score) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
}

function sortFindings(findings) {
    const { by, order } = AppState.currentSort;

    findings.sort((a, b) => {
        let valA, valB;

        if (by === 'cvss') {
            valA = a.cvss_score || 0;
            valB = b.cvss_score || 0;
        } else if (by === 'epss') {
            valA = a.epss_score || 0;
            valB = b.epss_score || 0;
        } else if (by === 'cve_id') {
            valA = a.cve_id || '';
            valB = b.cve_id || '';
        } else if (by === 'package_name') {
            valA = a.package_name || '';
            valB = b.package_name || '';
        } else if (by === 'kev') {
            // KEV: true가 먼저 오도록 (desc: KEV 먼저)
            valA = a.is_kev ? 1 : 0;
            valB = b.is_kev ? 1 : 0;
        } else if (by === 'poc') {
            // PoC: 있는 것이 먼저
            valA = a.has_exploit ? (a.exploit_count || 1) : 0;
            valB = b.has_exploit ? (b.exploit_count || 1) : 0;
        } else if (by === 'running') {
            // 실행상태: 실행중 > 사용날짜있음 > 없음
            valA = a.pkg_is_running ? 2 : (a.pkg_last_used ? 1 : 0);
            valB = b.pkg_is_running ? 2 : (b.pkg_last_used ? 1 : 0);
        }

        if (typeof valA === 'string') {
            return order === 'desc' ? valB.localeCompare(valA) : valA.localeCompare(valB);
        } else {
            return order === 'desc' ? valB - valA : valA - valB;
        }
    });
}

function updateStats(findings) {
    if (!findings || findings.length === 0) {
        document.getElementById('dashboardStats').style.display = 'none';
        return;
    }

    let high = 0, medium = 0, low = 0;

    findings.forEach(f => {
        const cvss = f.cvss_score || 0;
        if (cvss >= 7.0) high++;
        else if (cvss >= 4.0) medium++;
        else low++;
    });

    document.getElementById('highCount').textContent = high;
    document.getElementById('mediumCount').textContent = medium;
    document.getElementById('lowCount').textContent = low;
    document.getElementById('totalCves').textContent = findings.length;
    document.getElementById('dashboardStats').style.display = 'flex';
}

// ==================== PoC Batch Scanning ====================
async function scanAllPoCs() {
    if (AppState.pocScanning) {
        showToast('PoC 스캔이 이미 진행 중입니다', 'warning');
        return;
    }

    if (!AppState.currentFindings || AppState.currentFindings.length === 0) {
        showToast('스캔할 CVE가 없습니다', 'warning');
        return;
    }

    // CVE ID 목록 추출
    const cveIds = [...new Set(AppState.currentFindings.map(f => f.cve_id).filter(id => id))];

    if (cveIds.length === 0) {
        showToast('스캔할 CVE ID가 없습니다', 'warning');
        return;
    }

    AppState.pocScanning = true;
    AppState.pocScanProgress = 0;
    updatePocScanUI();

    try {
        showToast(`${cveIds.length}개 CVE에 대한 PoC 검색을 시작합니다...`, 'info');

        // 50개씩 배치로 나누어 처리
        const batchSize = 50;
        const batches = [];
        for (let i = 0; i < cveIds.length; i += batchSize) {
            batches.push(cveIds.slice(i, i + batchSize));
        }

        let totalProcessed = 0;
        let foundCount = 0;

        for (const batch of batches) {
            try {
                const result = await apiCall('/api/remote/exploit/batch-search', {
                    method: 'POST',
                    body: JSON.stringify(batch)
                });

                // 결과 처리
                const results = result.results || {};
                for (const [cveId, pocData] of Object.entries(results)) {
                    if (pocData.has_exploit) {
                        foundCount++;
                        // findings에 PoC 정보 업데이트
                        AppState.currentFindings.forEach(f => {
                            if (f.cve_id === cveId) {
                                f.has_exploit = pocData.has_exploit;
                                f.exploit_count = pocData.exploit_count;
                            }
                        });
                    }
                }

                totalProcessed += batch.length;
                AppState.pocScanProgress = Math.round((totalProcessed / cveIds.length) * 100);
                updatePocScanUI();

                // UI 업데이트를 위한 짧은 대기
                await new Promise(resolve => setTimeout(resolve, 100));

            } catch (error) {
                console.error('Batch PoC scan error:', error);
                showToast(`배치 검색 중 오류: ${error.message}`, 'error');
            }
        }

        // 스캔 완료
        AppState.pocScanning = false;
        updatePocScanUI();

        // UI 업데이트
        renderFindings(AppState.currentFindings);
        updateStats(AppState.currentFindings);

        showToast(`PoC 스캔 완료! ${foundCount}개 CVE에서 exploit 발견`, 'success');

    } catch (error) {
        AppState.pocScanning = false;
        updatePocScanUI();
        showToast(`PoC 배치 스캔 실패: ${error.message}`, 'error');
    }
}

function updatePocScanUI() {
    const btn = document.getElementById('scanPocBtn');
    if (!btn) return;

    if (AppState.pocScanning) {
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>${AppState.pocScanProgress}%`;
        btn.disabled = true;
        btn.className = 'btn btn-sm btn-warning';
    } else {
        btn.innerHTML = '<i class="bi bi-search me-1"></i>PoC 스캔';
        btn.disabled = !AppState.selectedHostId || !AppState.currentFindings.length;
        btn.className = 'btn btn-sm btn-outline-danger';
    }
}

// ==================== Sorting ====================
document.querySelectorAll('.sortable').forEach(th => {
    th.addEventListener('click', function () {
        const sortBy = this.dataset.sort;

        if (AppState.currentSort.by === sortBy) {
            AppState.currentSort.order = AppState.currentSort.order === 'desc' ? 'asc' : 'desc';
        } else {
            AppState.currentSort.by = sortBy;
            AppState.currentSort.order = 'desc';
        }

        updateSortIcons();
        renderFindings(AppState.currentFindings);
    });
});

function updateSortIcons() {
    document.querySelectorAll('.sortable').forEach(th => {
        const sortBy = th.dataset.sort;
        const sortIcon = th.querySelector('.sort-icon');
        const icon = sortIcon?.querySelector('i');

        if (!sortIcon || !icon) return;

        if (sortBy === AppState.currentSort.by) {
            sortIcon.classList.add('active');
            icon.className = AppState.currentSort.order === 'desc' ?
                'bi bi-chevron-down' : 'bi bi-chevron-up';
        } else {
            sortIcon.classList.remove('active');
            icon.className = 'bi bi-chevron-down';
        }
    });
}

// ==================== Host Modal ====================
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

function editHost(hostId) {
    const host = AppState.hosts.find(h => h.id === hostId);
    if (!host) return;

    document.getElementById('hostModalTitle').innerHTML = '<i class="bi bi-pencil me-1"></i>호스트 편집';
    document.getElementById('hostId').value = host.id;
    document.getElementById('hostHostname').value = host.hostname;
    document.getElementById('hostIpAddress').value = host.ip_address;
    document.getElementById('hostSshPort').value = host.ssh_port || 22;
    document.getElementById('hostSshUsername').value = host.ssh_username || 'root';
    document.getElementById('hostAuthMethod').value = host.ssh_password ? 'password' : 'key';
    document.getElementById('hostSshKeyPath').value = host.ssh_key_path || '';
    document.getElementById('hostSshPassword').value = '';
    document.getElementById('hostTags').value = host.tags || '';
    document.getElementById('hostDescription').value = host.description || '';
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

    const data = {
        hostname: document.getElementById('hostHostname').value,
        ip_address: document.getElementById('hostIpAddress').value,
        ssh_port: parseInt(document.getElementById('hostSshPort').value) || 22,
        ssh_username: document.getElementById('hostSshUsername').value || 'root',
        auth_method: authMethod,
        ssh_key_path: authMethod === 'key' ? document.getElementById('hostSshKeyPath').value : null,
        ssh_password: authMethod === 'password' ? document.getElementById('hostSshPassword').value : null,
        tags: document.getElementById('hostTags').value || null,
        description: document.getElementById('hostDescription').value || null,
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
            document.getElementById('selectedHostInfo').style.display = 'none';
            document.getElementById('findingsBody').innerHTML =
                '<tr><td colspan="9" class="text-center text-muted py-5"><i class="bi bi-search fs-1 d-block mb-2"></i><p>호스트를 선택하세요</p></td></tr>';
        }

        loadRemoteHosts();

    } catch (error) {
        showToast('삭제 실패: ' + error.message, 'error');
    }
}

// ==================== CVE Detail Modal ====================
async function showCveDetail(cveId) {
    const modal = new bootstrap.Modal(document.getElementById('cveDetailModal'));
    document.getElementById('cveDetailTitle').textContent = cveId;
    document.getElementById('cveDetailBody').innerHTML = '<div class="text-center py-4"><div class="spinner-border"></div></div>';

    modal.show();

    try {
        const data = await apiCall(`/api/cve/${cveId}`);

        document.getElementById('cveDetailBody').innerHTML = `
            <div class="row mb-3">
                <div class="col-md-6">
                    <h6>기본 정보</h6>
                    <p><strong>CVE ID:</strong> <a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank">${cveId}</a></p>
                    <p><strong>CVSS:</strong> ${data.cvss?.toFixed(1) || '-'} 
                       ${data.severity ? `<span class="badge bg-${data.severity === 'HIGH' || data.severity === 'CRITICAL' ? 'danger' : data.severity === 'MEDIUM' ? 'warning' : 'secondary'}">${data.severity}</span>` : ''}
                    </p>
                    <p><strong>EPSS:</strong> ${data.epss ? (data.epss * 100).toFixed(4) + '%' : '-'}</p>
                    <p><strong>KEV:</strong> ${data.is_kev ? '<span class="badge bg-danger">예</span>' : '아니오'}</p>
                </div>
                <div class="col-md-6">
                    <h6>공격 벡터</h6>
                    <p><strong>Attack Vector:</strong> ${data.attack_vector || '-'}</p>
                    <p><strong>Attack Complexity:</strong> ${data.attack_complexity || '-'}</p>
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
                        ${data.references.filter(ref => ref && (ref.startsWith('http://') || ref.startsWith('https://'))).slice(0, 10).map(ref => `<li><a href="${ref}" target="_blank" rel="noopener noreferrer" class="text-break">${ref}</a></li>`).join('')}
                        ${data.references.filter(ref => ref && !(ref.startsWith('http://') || ref.startsWith('https://'))).length > 0 ? `
                            <li class="text-muted"><small>기타 ${data.references.filter(ref => ref && !(ref.startsWith('http://') || ref.startsWith('https://'))).length}개의 참조가 있습니다</small></li>
                        ` : ''}
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

// ==================== Export ====================
function exportCsv() {
    if (!AppState.currentFindings || AppState.currentFindings.length === 0) {
        showToast('내보낼 데이터가 없습니다', 'warning');
        return;
    }

    const headers = ['Package', 'Version', 'CVE ID', 'CVSS', 'EPSS', 'KEV', 'Collector', 'Running', 'Last Used'];
    const rows = AppState.currentFindings.map(f => [
        f.package_name || '',
        f.package_version || '',
        f.cve_id || '',
        f.cvss_score || '',
        f.epss_score || '',
        f.is_kev ? 'Yes' : 'No',
        f.collector_mode || '',
        f.pkg_is_running ? 'Yes' : 'No',
        f.pkg_last_used || ''
    ]);

    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');

    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `vulnerabilities_${Date.now()}.csv`;
    link.click();

    showToast('CSV 파일 다운로드 시작', 'success');
}

async function exportPdf() {
    if (!AppState.selectedHostId) {
        showToast('호스트를 선택하세요', 'warning');
        return;
    }

    try {
        const response = await fetch(`/api/remote/report/${AppState.selectedHostId}/pdf`);
        if (!response.ok) throw new Error('PDF 생성 실패');

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `report_${AppState.selectedHostId}_${Date.now()}.pdf`;
        link.click();

        showToast('PDF 다운로드 시작', 'success');
    } catch (error) {
        showToast('PDF 생성 실패: ' + error.message, 'error');
    }
}

// ==================== SBOM Viewer ====================
let currentSbomData = null;

async function showSbomViewer() {
    if (!AppState.selectedHostId) {
        showToast('호스트를 먼저 선택하세요', 'warning');
        return;
    }

    const modal = new bootstrap.Modal(document.getElementById('sbomModal'));
    modal.show();

    const bodyEl = document.getElementById('sbomBody');
    bodyEl.innerHTML = '<div class="text-center py-4"><div class="spinner-border"></div><p class="mt-2">SBOM 로딩 중...</p></div>';

    try {
        const response = await fetch(`/api/remote/sbom/${AppState.selectedHostId}`);
        if (!response.ok) throw new Error('SBOM 로드 실패');

        currentSbomData = await response.json();
        renderSbom(currentSbomData);
    } catch (error) {
        const detail = error.detail || error.message;
        bodyEl.innerHTML = `
            <div class="alert alert-danger">
                <h6 class="alert-heading"><i class="bi bi-exclamation-triangle me-2"></i>SBOM 로드 실패</h6>
                <p class="mb-2">${detail}</p>
                <hr>
                <small class="text-muted">가능한 원인:</small>
                <ul class="small mb-0">
                    <li>호스트 스캔이 아직 실행되지 않았습니다</li>
                    <li>스캔이 실패했습니다 (스캔 작업 현황 확인)</li>
                    <li>데이터베이스 연결 오류</li>
                </ul>
            </div>
        `;
        console.error('SBOM load error:', error);
    }
}

function renderSbom(sbom) {
    const bodyEl = document.getElementById('sbomBody');

    // SBOM 메타데이터
    const metadata = sbom.metadata || {};
    const timestamp = metadata.timestamp || 'N/A';
    const toolsHtml = (metadata.tools || []).map(t => `<li>${t.name} ${t.version || ''}</li>`).join('');

    // 취약점 통계 추출
    const metaProps = metadata.properties || [];
    const stats = {
        total: parseInt(metaProps.find(p => p.name === 'total_vulnerabilities')?.value || '0'),
        critical: parseInt(metaProps.find(p => p.name === 'critical_count')?.value || '0'),
        high: parseInt(metaProps.find(p => p.name === 'high_count')?.value || '0'),
        medium: parseInt(metaProps.find(p => p.name === 'medium_count')?.value || '0'),
        low: parseInt(metaProps.find(p => p.name === 'low_count')?.value || '0'),
        kev: parseInt(metaProps.find(p => p.name === 'kev_count')?.value || '0')
    };

    // 컴포넌트 분류
    const components = sbom.components || [];
    const vulnerabilities = sbom.vulnerabilities || [];
    const osComponents = components.filter(c => c.type === 'operating-system');
    const kernelComponents = components.filter(c => c.type === 'platform' || c.name === 'linux-kernel');
    const packageComponents = components.filter(c =>
        c.type === 'library' && c.name !== 'linux-kernel'  // linux-kernel은 커널 섹션으로
    );

    // 커널 CVE 개수 계산
    let kernelCveCount = 0;
    kernelComponents.forEach(k => {
        const vulnProp = k.properties?.find(p => p.name === 'vulnerabilities_count');
        if (vulnProp) kernelCveCount += parseInt(vulnProp.value || '0');
    });

    let html = `
        <!-- 취약점 통계 대시보드 -->
        <div class="p-3 mb-4 rounded" style="background-color: #f5f5f7;">
            <h6 class="mb-3 text-secondary">
                취약점 통계
            </h6>
            <div class="row text-center">
                <div class="col">
                    <h3 class="mb-0">${stats.total}</h3>
                    <small class="text-muted">전체</small>
                </div>
                <div class="col">
                    <h3 class="mb-0 text-danger">${stats.critical}</h3>
                    <small class="text-danger">Critical</small>
                </div>
                <div class="col">
                    <h3 class="mb-0 text-warning">${stats.high}</h3>
                    <small class="text-warning">High</small>
                </div>
                <div class="col">
                    <h3 class="mb-0 text-info">${stats.medium}</h3>
                    <small class="text-muted">Medium</small>
                </div>
                <div class="col">
                    <h3 class="mb-0 text-secondary">${stats.low}</h3>
                    <small class="text-muted">Low</small>
                </div>
                <div class="col border-start">
                    <h3 class="mb-0 text-danger">${stats.kev}</h3>
                    <small class="text-danger">KEV</small>
                </div>
            </div>
        </div>
        
        <div class="mb-4">
            <h6 class="border-bottom pb-2"><i class="bi bi-info-circle me-2"></i>메타데이터</h6>
            <div class="row">
                <div class="col-md-6">
                    <p class="mb-1"><strong>포맷:</strong> CycloneDX ${sbom.specVersion || 'N/A'}</p>
                    <p class="mb-1"><strong>시리얼:</strong> <code class="small">${sbom.serialNumber || 'N/A'}</code></p>
                </div>
                <div class="col-md-6">
                    <p class="mb-1"><strong>생성시각:</strong> ${new Date(timestamp).toLocaleString('ko-KR')}</p>
                    <p class="mb-1"><strong>도구:</strong></p>
                    <ul class="small mb-0">${toolsHtml || '<li>N/A</li>'}</ul>
                </div>
            </div>
        </div>

        <div class="mb-4">
            <h6 class="border-bottom pb-2">
                <i class="bi bi-hdd-fill me-2 text-primary"></i>운영체제
            </h6>
            ${renderComponentTable(osComponents, vulnerabilities)}
        </div>

        <div class="mb-4">
            <h6 class="border-bottom pb-2">
                <i class="bi bi-cpu me-2 text-success"></i>커널
                ${kernelCveCount > 0 ? `<span class="badge bg-danger">${kernelCveCount} CVE</span>` : ''}
            </h6>
            ${renderComponentTable(kernelComponents, vulnerabilities, true)}
        </div>

        <div class="mb-4">
            <h6 class="border-bottom pb-2">
                <i class="bi bi-box-seam me-2 text-info"></i>패키지
                <span class="badge bg-info">${packageComponents.length}</span>
            </h6>
            ${renderComponentTable(packageComponents, vulnerabilities)}
        </div>

        <div class="mb-3">
            <h6 class="border-bottom pb-2"><i class="bi bi-file-earmark-code me-2"></i>원본 JSON</h6>
            <div class="bg-light p-3 rounded" style="max-height: 300px; overflow-y: auto;">
                <pre class="mb-0" style="font-size: 0.75rem;"><code>${JSON.stringify(sbom, null, 2)}</code></pre>
            </div>
        </div>
    `;

    bodyEl.innerHTML = html;
}

function renderComponentTable(components, vulnerabilities, isKernel = false) {
    if (components.length === 0) {
        return '<p class="text-muted small">컴포넌트 없음</p>';
    }

    // CVE 개수순으로 정렬
    const sortedComponents = [...components].sort((a, b) => {
        const aVuln = parseInt(a.properties?.find(p => p.name === 'vulnerabilities_count')?.value || '0');
        const bVuln = parseInt(b.properties?.find(p => p.name === 'vulnerabilities_count')?.value || '0');
        return bVuln - aVuln;
    });

    // 패키지가 많을 경우 초기에는 20개만 표시
    const INITIAL_DISPLAY = 20;
    const shouldPaginate = sortedComponents.length > INITIAL_DISPLAY;
    const tableId = isKernel ? 'kernel-table' : `component-table-${Math.random().toString(36).substr(2, 9)}`;

    const renderRows = (components, start = 0, end = components.length) => {
        return components.slice(start, end).map(c => {
            // CPE 찾기
            let cpe = '';
            if (c.properties) {
                const cpeProperty = c.properties.find(p => p.name === 'cpe');
                if (cpeProperty) cpe = cpeProperty.value;
            }

            // 취약점 개수 찾기
            let vulnCount = 0;
            let criticalCount = 0;
            let highCount = 0;

            if (c.properties) {
                const vulnProp = c.properties.find(p => p.name === 'vulnerabilities_count');
                const criticalProp = c.properties.find(p => p.name === 'critical_cves');
                const highProp = c.properties.find(p => p.name === 'high_cves');

                if (vulnProp) vulnCount = parseInt(vulnProp.value || '0');
                if (criticalProp) criticalCount = parseInt(criticalProp.value || '0');
                if (highProp) highCount = parseInt(highProp.value || '0');
            }

            // CVE 배지 (항상 숫자 표시)
            let vulnBadge;
            if (vulnCount > 0) {
                vulnBadge = `
                    <span class="badge ${criticalCount > 0 ? 'bg-danger' : highCount > 0 ? 'bg-warning text-dark' : 'bg-secondary'}">
                        ${vulnCount} CVE
                    </span>
                `;
            } else {
                vulnBadge = '<span class="badge bg-light text-muted">0 CVE</span>';
            }

            // 커널 컴포넌트는 이름을 "Linux Kernel"로 표시
            let displayName = c.name || 'N/A';
            if (isKernel && (c.name === 'linux-kernel' || c.type === 'platform')) {
                displayName = 'Linux Kernel';
            }

            return `
                <tr class="${criticalCount > 0 ? 'table-danger' : highCount > 0 ? 'table-warning' : ''}">
                    <td>
                        <strong>${displayName}</strong>
                        ${vulnBadge}
                    </td>
                    <td>${c.version || 'N/A'}</td>
                    <td><code class="small text-break">${cpe || '-'}</code></td>
                </tr>
            `;
        }).join('');
    };

    const initialRows = renderRows(sortedComponents, 0, Math.min(INITIAL_DISPLAY, sortedComponents.length));
    const loadMoreButton = shouldPaginate ? `
        <div class="text-center my-3" id="${tableId}-load-more">
            <button class="btn btn-outline-primary btn-sm" onclick="loadMoreComponents('${tableId}', ${INITIAL_DISPLAY}, ${sortedComponents.length})">
                <i class="bi bi-chevron-down me-1"></i>
                더보기 (${sortedComponents.length - INITIAL_DISPLAY}개 남음)
            </button>
        </div>
    ` : '';

    // 남은 데이터를 data 속성에 저장
    const remainingData = shouldPaginate ? JSON.stringify(sortedComponents.slice(INITIAL_DISPLAY)) : '[]';

    return `
        <div class="table-responsive">
            <table class="table table-sm table-hover" id="${tableId}">
                <thead class="table-light">
                    <tr>
                        <th style="width: 40%;">Name</th>
                        <th style="width: 20%;">Version</th>
                        <th style="width: 40%;">CPE</th>
                    </tr>
                </thead>
                <tbody>${initialRows}</tbody>
            </table>
            <div id="${tableId}-remaining-data" style="display:none;">${remainingData}</div>
            ${loadMoreButton}
        </div>
    `;
}

// 더보기 버튼 클릭 시 호출되는 함수
function loadMoreComponents(tableId, currentCount, totalCount) {
    const table = document.getElementById(tableId);
    const tbody = table.querySelector('tbody');
    const remainingDataEl = document.getElementById(`${tableId}-remaining-data`);
    const loadMoreDiv = document.getElementById(`${tableId}-load-more`);

    try {
        const remainingComponents = JSON.parse(remainingDataEl.textContent);

        // 다음 20개 로드
        const BATCH_SIZE = 20;
        const nextBatch = remainingComponents.slice(0, BATCH_SIZE);
        const stillRemaining = remainingComponents.slice(BATCH_SIZE);

        // 테이블에 추가
        nextBatch.forEach(c => {
            let cpe = '';
            if (c.properties) {
                const cpeProperty = c.properties.find(p => p.name === 'cpe');
                if (cpeProperty) cpe = cpeProperty.value;
            }

            let vulnCount = 0;
            let criticalCount = 0;
            let highCount = 0;

            if (c.properties) {
                const vulnProp = c.properties.find(p => p.name === 'vulnerabilities_count');
                const criticalProp = c.properties.find(p => p.name === 'critical_cves');
                const highProp = c.properties.find(p => p.name === 'high_cves');

                if (vulnProp) vulnCount = parseInt(vulnProp.value || '0');
                if (criticalProp) criticalCount = parseInt(criticalProp.value || '0');
                if (highProp) highCount = parseInt(highProp.value || '0');
            }

            let vulnBadge;
            if (vulnCount > 0) {
                vulnBadge = `
                    <span class="badge ${criticalCount > 0 ? 'bg-danger' : highCount > 0 ? 'bg-warning text-dark' : 'bg-secondary'}">
                        ${vulnCount} CVE
                    </span>
                `;
            } else {
                vulnBadge = '<span class="badge bg-light text-muted">0 CVE</span>';
            }

            const row = document.createElement('tr');
            row.className = criticalCount > 0 ? 'table-danger' : highCount > 0 ? 'table-warning' : '';
            row.innerHTML = `
                <td>
                    <strong>${c.name || 'N/A'}</strong>
                    ${vulnBadge}
                </td>
                <td>${c.version || 'N/A'}</td>
                <td><code class="small text-break">${cpe || '-'}</code></td>
            `;
            tbody.appendChild(row);
        });

        // 남은 데이터 업데이트
        remainingDataEl.textContent = JSON.stringify(stillRemaining);

        // 버튼 업데이트
        if (stillRemaining.length === 0) {
            loadMoreDiv.innerHTML = '<p class="text-muted text-center small mb-0">모든 패키지를 불러왔습니다.</p>';
        } else {
            const newCount = currentCount + BATCH_SIZE;
            loadMoreDiv.innerHTML = `
                <button class="btn btn-outline-primary btn-sm" onclick="loadMoreComponents('${tableId}', ${newCount}, ${totalCount})">
                    <i class="bi bi-chevron-down me-1"></i>
                    더보기 (${stillRemaining.length}개 남음)
                </button>
            `;
        }
    } catch (error) {
        console.error('Failed to load more components:', error);
        showToast('데이터 로드 실패', 'danger');
    }
}

function downloadSbom() {
    if (!currentSbomData) {
        showToast('SBOM 데이터가 없습니다', 'warning');
        return;
    }

    // 순수 SBOM (모든 패키지 정보) - 취약점 정보만 제외
    const pureSbom = {
        bomFormat: currentSbomData.bomFormat,
        specVersion: currentSbomData.specVersion,
        serialNumber: currentSbomData.serialNumber,
        version: currentSbomData.version,
        metadata: {
            timestamp: currentSbomData.metadata?.timestamp,
            component: currentSbomData.metadata?.component,
            tools: currentSbomData.metadata?.tools,
            properties: [
                { name: "total_components", value: String(currentSbomData.components?.length || 0) },
                { name: "scan_type", value: "agentless_remote" }
            ]
        },
        // 모든 컴포넌트 포함 (OS, 커널, 패키지 전부)
        components: (currentSbomData.components || []).map(c => {
            const cleanComponent = {
                "bom-ref": c["bom-ref"],
                type: c.type,
                name: c.name,
                version: c.version
            };

            // PURL 추가 (있으면)
            if (c.purl) cleanComponent.purl = c.purl;

            // 패키지 관리자, CPE, architecture 같은 메타데이터만 포함 (CVE 통계 제외)
            const allowedProps = ['package_manager', 'cpe', 'architecture', 'kernel', 'supplier', 'license', 'checksum'];
            const filteredProps = (c.properties || []).filter(p =>
                allowedProps.includes(p.name) &&
                !['vulnerabilities_count', 'critical_cves', 'high_cves', 'running'].includes(p.name)
            );
            if (filteredProps.length > 0) {
                cleanComponent.properties = filteredProps;
            }

            // hashes 추가 (있으면)
            if (c.hashes) cleanComponent.hashes = c.hashes;

            return cleanComponent;
        })
        // vulnerabilities 필드 완전 제외 - SBOM은 구성 요소 목록일 뿐
    };

    const blob = new Blob([JSON.stringify(pureSbom, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `sbom_host_${AppState.selectedHostId}_${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);

    showToast('SBOM JSON 다운로드 (패키지 정보만)', 'success');
}

// ==================== Job Error Display ====================
async function showJobError(jobId) {
    try {
        const job = await apiCall(`/api/remote/jobs/${jobId}`);

        const modalHtml = `
            <div class="modal fade" id="jobErrorModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header bg-danger text-white">
                            <h5 class="modal-title">
                                <i class="bi bi-exclamation-octagon me-2"></i>스캔 작업 실패 상세
                            </h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <h6>작업 정보</h6>
                            <table class="table table-sm">
                                <tr><th style="width: 150px;">Job ID</th><td>#${job.id}</td></tr>
                                <tr><th>호스트</th><td>${job.hostname || 'N/A'}</td></tr>
                                <tr><th>프리셋</th><td>${job.preset || 'standard'}</td></tr>
                                <tr><th>시작 시각</th><td>${formatDateTime(job.started_at)}</td></tr>
                                <tr><th>실패 시각</th><td>${formatDateTime(job.completed_at)}</td></tr>
                                <tr><th>진행 단계</th><td>${job.current_phase || 'unknown'}</td></tr>
                            </table>
                            
                            <h6 class="mt-3">에러 메시지</h6>
                            <div class="alert alert-danger">
                                <pre class="mb-0" style="white-space: pre-wrap; font-size: 0.85rem;">${escapeHtml(job.error_message || '에러 메시지 없음')}</pre>
                            </div>
                            
                            ${job.progress_message ? `
                                <h6>마지막 진행 메시지</h6>
                                <div class="alert alert-secondary">
                                    <small>${escapeHtml(job.progress_message)}</small>
                                </div>
                            ` : ''}
                        </div>
                        <div class="modal-footer">
                            <button class="btn btn-secondary" data-bs-dismiss="modal">닫기</button>
                            <button class="btn btn-primary" onclick="retryJob(${job.id}, ${job.host_id})" data-bs-dismiss="modal">
                                <i class="bi bi-arrow-clockwise me-1"></i>재시도
                            </button>
                        </div>
                    </div >
                </div >
            </div >
        `;

        // 기존 모달 제거
        const existing = document.getElementById('jobErrorModal');
        if (existing) existing.remove();

        // 새 모달 추가
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('jobErrorModal'));
        modal.show();

        // 모달 닫힐 때 제거
        document.getElementById('jobErrorModal').addEventListener('hidden.bs.modal', function () {
            this.remove();
        });

    } catch (error) {
        showToast('작업 정보를 불러올 수 없습니다', 'error');
        console.error('Job error display failed:', error);
    }
}

async function retryJob(jobId, hostId) {
    const preset = 'deep';
    await startRemoteScan(hostId);
}

// ==================== Initialization ====================
document.addEventListener('DOMContentLoaded', async function () {
    console.log('Remote CVE Scanner Initializing...');

    await loadRemoteHosts();
    await loadScanJobs();

    // CVE 년도 슬라이더 이벤트 리스너
    const cveYearStart = document.getElementById('cveYearStart');
    const cveYearRange = document.getElementById('cveYearRange');

    if (cveYearStart && cveYearRange) {
        // 초기값 설정
        const currentYear = new Date().getFullYear();
        cveYearStart.max = currentYear;

        const updateYearRange = () => {
            const startYear = parseInt(cveYearStart.value);
            if (startYear === 1999) {
                cveYearRange.textContent = '전체 기간 (1999 ~ ' + currentYear + ')';
            } else {
                cveYearRange.textContent = startYear + ' ~ ' + currentYear;
            }
        };

        updateYearRange();
        cveYearStart.addEventListener('input', updateYearRange);
    }

    // 주기적으로 작업 목록 갱신 (5초마다)
    setInterval(loadScanJobs, 5000);

    console.log('App Initialized');
});

// ==================== 스캔 히스토리 ====================

// 비교용 선택된 스캔들
let selectedScans = [];
let currentScanHistory = [];
let currentHistoryHostname = '';

async function showScanHistory() {
    if (!AppState.selectedHostId) {
        showToast('호스트를 먼저 선택하세요', 'warning');
        return;
    }

    selectedScans = [];
    updateScanSelectionUI();

    // 현재 선택된 호스트 정보 가져오기
    const selectedHost = AppState.hosts.find(h => h.id === AppState.selectedHostId);
    const hostDisplayName = selectedHost ? (selectedHost.hostname || selectedHost.ip_address) : '';

    const modalEl = document.getElementById('scanHistoryModal');
    const modal = new bootstrap.Modal(modalEl);
    const tbody = document.getElementById('scanHistoryBody');
    const modalTitle = modalEl.querySelector('.modal-title');

    // 모달 표시 전에 호스트명 먼저 설정
    if (modalTitle && hostDisplayName) {
        modalTitle.innerHTML = `<i class="bi bi-clock-history me-2"></i>스캔 히스토리 - <strong>${escapeHtml(hostDisplayName)}</strong>`;
    }

    tbody.innerHTML = '<tr><td colspan="7" class="text-center py-3"><span class="spinner-border spinner-border-sm"></span> 로딩 중...</td></tr>';

    modal.show();

    try {
        const result = await apiCall(`/api/remote/hosts/${AppState.selectedHostId}/scan-history`);
        currentScanHistory = result.scans || [];
        currentHistoryHostname = result.hostname || hostDisplayName;

        // API 응답에서 호스트명이 있으면 업데이트
        if (result.hostname && modalTitle) {
            modalTitle.innerHTML = `<i class="bi bi-clock-history me-2"></i>스캔 히스토리 - <strong>${escapeHtml(result.hostname)}</strong>`;
        }

        renderScanHistoryTable(currentScanHistory);
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
        const isSelected = selectedScans.includes(scan.id);
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
                    <button class="btn btn-sm btn-outline-primary" onclick="viewScanResult(${scan.id})">
                        <i class="bi bi-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteScanRecord(${scan.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    tbody.innerHTML = rows;
}

function toggleScanSelection(scanId) {
    const idx = selectedScans.indexOf(scanId);
    if (idx >= 0) {
        selectedScans.splice(idx, 1);
    } else {
        if (selectedScans.length >= 2) {
            selectedScans.shift();
        }
        selectedScans.push(scanId);
    }

    updateScanSelectionUI();
    renderScanHistoryTable(currentScanHistory);
}

function updateScanSelectionUI() {
    const infoEl = document.getElementById('scanSelectionInfo');
    const compareBtn = document.getElementById('compareScansBtn');
    if (infoEl) infoEl.textContent = `${selectedScans.length}개 선택됨`;
    if (compareBtn) compareBtn.disabled = selectedScans.length !== 2;
}

async function viewScanResult(scanId) {
    // 해당 스캔의 취약점을 메인 테이블에 표시
    AppState.selectedScanId = scanId;

    bootstrap.Modal.getInstance(document.getElementById('scanHistoryModal')).hide();

    await loadHostFindings(AppState.selectedHostId);
    showToast(`스캔 #${scanId} 결과 표시`, 'info');
}

async function deleteScanRecord(scanId) {
    if (!confirm(`스캔 #${scanId}를 삭제하시겠습니까?\n관련된 모든 취약점 데이터도 삭제됩니다.`)) {
        return;
    }

    try {
        await apiCall(`/api/scan-history/${scanId}`, { method: 'DELETE' });
        showToast('스캔 기록 삭제 완료', 'success');

        selectedScans = selectedScans.filter(id => id !== scanId);
        updateScanSelectionUI();

        const result = await apiCall(`/api/remote/hosts/${AppState.selectedHostId}/scan-history`);
        currentScanHistory = result.scans || [];
        renderScanHistoryTable(currentScanHistory);
    } catch (error) {
        showToast('삭제 실패: ' + error.message, 'error');
    }
}

async function compareSelectedScans() {
    if (selectedScans.length !== 2) {
        showToast('비교할 스캔 2개를 선택하세요', 'warning');
        return;
    }

    const [scan1, scan2] = selectedScans;
    const hostId = AppState.selectedHostId;

    bootstrap.Modal.getInstance(document.getElementById('scanHistoryModal')).hide();

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
                ${renderCompareVulnList(newVulns, 'danger')}
            </div>
            <div class="tab-pane fade" id="resolvedVulnsTab">
                ${renderCompareVulnList(resolvedVulns, 'success')}
            </div>
            <div class="tab-pane fade" id="unchangedVulnsTab">
                ${renderCompareVulnList(unchangedVulns, 'warning')}
            </div>
        </div>
    `;

    container.innerHTML = html;

    // 비교 결과 저장 (CSV 내보내기용)
    window.lastCompareResult = result;
}

function renderCompareVulnList(vulns, colorClass) {
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
            <td><span class="${getCvssClass(cvss)}">${cvss >= 9 ? 'Critical' : cvss >= 7 ? 'High' : cvss >= 4 ? 'Medium' : 'Low'}</span></td>
        </tr>
    `}).join('');

    return `
        <table class="table table-sm table-hover mb-0">
            <thead class="table-${colorClass}">
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

function exportCompareResult() {
    if (!window.lastCompareResult) {
        showToast('비교 결과가 없습니다', 'warning');
        return;
    }

    const result = window.lastCompareResult;
    const rows = [];

    const getCvss = (v) => (v.cvss_score || v.cvss || 0).toFixed(1);

    (result.new || []).forEach(v => rows.push([v.package_name, v.cve_id, getCvss(v), '신규']));
    (result.resolved || []).forEach(v => rows.push([v.package_name, v.cve_id, getCvss(v), '해결']));
    (result.unchanged || []).forEach(v => rows.push([v.package_name, v.cve_id, getCvss(v), '미해결']));

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

// 전역 함수로 노출
window.showAddHostModal = showAddHostModal;
window.editHost = editHost;
window.toggleAuthMethod = toggleAuthMethod;
window.saveHost = saveHost;
window.deleteHost = deleteHost;
window.selectHost = selectHost;
window.selectJob = selectJob;
window.startRemoteScan = startRemoteScan;
window.showCveDetail = showCveDetail;
window.exportCsv = exportCsv;
window.exportPdf = exportPdf;
window.loadRemoteHosts = loadRemoteHosts;
window.showSbomViewer = showSbomViewer;
window.downloadSbom = downloadSbom;
window.showJobError = showJobError;
window.retryJob = retryJob;
// 스캔 히스토리 관련
window.showScanHistory = showScanHistory;
window.toggleScanSelection = toggleScanSelection;
window.viewScanResult = viewScanResult;
window.deleteScanRecord = deleteScanRecord;
window.compareSelectedScans = compareSelectedScans;
window.exportCompareResult = exportCompareResult;

// ==================== NVD 데이터 다운로드 ====================

async function downloadNvdRange() {
    const startYearSelect = document.getElementById('nvdStartYear');
    const endYearSelect = document.getElementById('nvdEndYear');
    const startYear = parseInt(startYearSelect.value);
    const endYear = parseInt(endYearSelect.value);
    const downloadBtn = document.getElementById('downloadNvdBtn');

    // 유효성 검사
    if (startYear > endYear) {
        showToast('시작 년도는 종료 년도보다 작거나 같아야 합니다.', 'error');
        return;
    }

    const yearCount = endYear - startYear + 1;
    const estimatedMinutes = Math.ceil(yearCount * 0.8); // 년도당 약 50초 = 0.8분

    if (!confirm(`${startYear}년부터 ${endYear}년까지 (총 ${yearCount}년) CVE 데이터를 다운로드하시겠습니까?\n\n예상 소요 시간: 약 ${estimatedMinutes}분\n백그라운드에서 진행됩니다.`)) {
        return;
    }

    // 진행 바 표시
    const progressDiv = document.getElementById('nvdDownloadProgress');
    const progressBar = document.getElementById('nvdProgressBar');
    const progressText = document.getElementById('nvdProgressText');
    const progressDetail = document.getElementById('nvdProgressDetail');

    progressDiv.style.display = 'block';
    progressBar.style.width = '0%';
    progressText.textContent = '다운로드 시작...';
    progressDetail.textContent = `${startYear}~${endYear}년 (${yearCount}년) 다운로드 준비 중...`;

    // 버튼 비활성화
    downloadBtn.disabled = true;
    downloadBtn.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>다운로드 중...';

    try {
        const result = await apiCall('/api/remote/nvd/download-range', {
            method: 'POST',
            body: JSON.stringify({
                start_year: startYear,
                end_year: endYear
            })
        });

        showToast(`${startYear}~${endYear}년 NVD 데이터 다운로드가 시작되었습니다.`, 'success');

        // 실제 진행 상황 폴링 (2초마다)
        let lastProgress = 0;
        const pollInterval = setInterval(async () => {
            try {
                const progress = await apiCall('/api/remote/nvd/download-progress');

                if (progress.status === 'running') {
                    const percent = Math.floor((progress.completed_years / progress.total_years) * 100);
                    progressBar.style.width = `${percent}%`;
                    progressText.textContent = `${percent}%`;
                    progressDetail.textContent = `${progress.current_year}년 다운로드 중... (${progress.completed_years}/${progress.total_years}년 완료)`;
                    lastProgress = percent;
                } else if (progress.status === 'completed') {
                    clearInterval(pollInterval);
                    progressBar.style.width = '100%';
                    progressText.textContent = '완료!';
                    progressDetail.textContent = progress.message;
                    showToast('NVD 데이터 다운로드가 완료되었습니다!', 'success');
                    setTimeout(() => {
                        progressDiv.style.display = 'none';
                        loadNvdDownloadRecords(); // 목록 갱신
                    }, 3000);
                } else if (progress.status === 'failed') {
                    clearInterval(pollInterval);
                    progressBar.style.width = `${lastProgress}%`;
                    progressBar.classList.add('bg-danger');
                    progressText.textContent = '오류';
                    progressDetail.textContent = progress.message;
                    showToast(`다운로드 실패: ${progress.message}`, 'error');
                }
            } catch (e) {
                console.error('진행 상황 조회 실패:', e);
            }
        }, 2000); // 2초마다 체크

        // 최대 시간 후 자동 정리
        setTimeout(() => {
            clearInterval(pollInterval);
            if (progressDiv.style.display !== 'none') {
                progressDiv.style.display = 'none';
            }
        }, estimatedMinutes * 60 * 1000 + 120000); // 예상 시간 + 2분

    } catch (error) {
        showToast(`다운로드 시작 실패: ${error.message}`, 'error');
        progressDiv.style.display = 'none';
    } finally {
        // 버튼 다시 활성화
        downloadBtn.disabled = false;
        downloadBtn.innerHTML = '<i class="bi bi-download me-1"></i>선택 범위 다운로드';
    }
}

async function showNvdManager() {
    const modal = new bootstrap.Modal(document.getElementById('nvdManagerModal'));
    modal.show();
    await loadNvdRecords();
}

async function loadNvdRecords() {
    const tableBody = document.getElementById('nvdRecordsTable');
    tableBody.innerHTML = `
        <tr>
            <td colspan="6" class="text-center text-muted">
                <i class="bi bi-hourglass-split me-1"></i>로딩 중...
            </td>
        </tr>
    `;

    try {
        const result = await apiCall('/api/remote/nvd/download-records');
        const records = result.records || [];

        if (records.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted">
                        <i class="bi bi-inbox me-1"></i>다운로드 기록이 없습니다.
                    </td>
                </tr>
            `;
            return;
        }

        let html = '';
        for (const record of records) {
            const downloadDate = new Date(record.downloaded_at);
            const formattedDate = downloadDate.toLocaleString('ko-KR', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            });

            html += `
                <tr>
                    <td><strong>${record.year}년</strong></td>
                    <td>${record.cve_count.toLocaleString()}개</td>
                    <td>${record.package_count.toLocaleString()}개</td>
                    <td>${record.size_mb.toFixed(2)} MB</td>
                    <td class="small text-muted">${formattedDate}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteNvdYear(${record.year})">
                            <i class="bi bi-trash me-1"></i>삭제
                        </button>
                    </td>
                </tr>
            `;
        }

        tableBody.innerHTML = html;

    } catch (error) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-danger">
                    <i class="bi bi-exclamation-triangle me-1"></i>로드 실패: ${error.message}
                </td>
            </tr>
        `;
    }
}

async function deleteNvdYear(year) {
    if (!confirm(`${year}년 데이터를 삭제하시겠습니까?\n\n이 작업은 되돌릴 수 없습니다.`)) {
        return;
    }

    try {
        await apiCall(`/api/remote/nvd/year/${year}`, {
            method: 'DELETE'
        });

        showToast(`${year}년 데이터가 삭제되었습니다.`, 'success');
        await loadNvdRecords();

    } catch (error) {
        showToast(`삭제 실패: ${error.message}`, 'error');
    }
}

// ==================== PoC/Exploit Functions ====================
let currentPocCveId = null;
let currentPocData = null;

async function searchPoc(cveId) {
    showToast(`${cveId} PoC 검색 중...`, 'info');

    try {
        const result = await apiCall(`/api/remote/exploit/search/${cveId}?use_cache=false`);

        if (result.has_exploit) {
            showToast(`${cveId}: ${result.exploit_count}개 PoC 발견!`, 'success');
            showPocModal(cveId, result);
        } else {
            showToast(`${cveId}: 알려진 PoC 없음`, 'warning');
        }

        // 현재 findings 새로고침
        if (AppState.selectedHostId) {
            loadHostFindings(AppState.selectedHostId, AppState.collectorFilter);
        }
    } catch (error) {
        showToast(`PoC 검색 실패: ${error.message}`, 'error');
    }
}

async function showPocModal(cveId, prefetchedData = null) {
    currentPocCveId = cveId;

    const pocModal = new bootstrap.Modal(document.getElementById('pocModal'));
    const pocContent = document.getElementById('pocContent');

    pocContent.innerHTML = `
        <div class="text-center py-4">
            <span class="spinner-border spinner-border-sm"></span> ${cveId} PoC 정보 조회 중...
            <div class="small text-muted mt-2">nomi-sec, GitHub, Exploit-DB, Nuclei 검색 중...</div>
        </div>
    `;
    pocModal.show();

    try {
        const data = prefetchedData || await apiCall(`/api/remote/exploit/search/${cveId}`);
        currentPocData = data;

        // 검색된 소스 표시
        const sourcesSearched = data.sources_searched || ['GitHub', 'Exploit-DB'];
        const sourcesHtml = sourcesSearched.length > 0
            ? `<span class="text-muted small">검색: ${sourcesSearched.join(', ')}</span>`
            : '';

        if (!data.has_exploit) {
            pocContent.innerHTML = `
                <div class="alert alert-info">
                    <i class="bi bi-info-circle me-1"></i>
                    <strong>${cveId}</strong>에 대한 공개된 PoC/Exploit이 발견되지 않았습니다.
                </div>
                <p class="small text-muted">
                    검색된 소스: ${sourcesSearched.join(', ')}
                </p>
            `;
            return;
        }

        let html = `
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h6 class="mb-0">
                    <span class="badge bg-danger me-2">${cveId}</span>
                    <span class="text-muted">${data.exploit_count}개의 Exploit/PoC 발견</span>
                </h6>
                ${sourcesHtml}
            </div>
        `;

        // Nuclei Template (있으면 먼저 표시)
        if (data.nuclei_template) {
            const nuclei = data.nuclei_template;
            html += `
                <div class="card mb-3 border-success">
                    <div class="card-header py-2 bg-success text-white">
                        <i class="bi bi-shield-check me-1"></i> Nuclei Template
                        <span class="badge bg-light text-dark ms-2">${nuclei.severity || 'unknown'}</span>
                    </div>
                    <div class="card-body py-2">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <strong>${escapeHtml(nuclei.name)}</strong>
                                <div class="small text-muted">nuclei 스캐너로 자동 탐지 가능</div>
                            </div>
                            <div class="btn-group btn-group-sm">
                                <a href="${nuclei.url}" target="_blank" class="btn btn-outline-success" title="템플릿 보기">
                                    <i class="bi bi-file-code"></i>
                                </a>
                                <a href="${nuclei.raw_url}" target="_blank" class="btn btn-outline-success" title="Raw 다운로드">
                                    <i class="bi bi-download"></i>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        // GitHub PoC 목록 (페이징 처리)
        if (data.github_pocs && data.github_pocs.length > 0) {
            const githubPocs = data.github_pocs;
            const pageSize = 5;
            const totalPages = Math.ceil(githubPocs.length / pageSize);

            html += `
                <div class="card mb-3" id="githubPocCard">
                    <div class="card-header py-2 bg-dark text-white d-flex justify-content-between align-items-center">
                        <span><i class="bi bi-github me-1"></i> GitHub PoC (${githubPocs.length}개)</span>
                        ${githubPocs.length > pageSize ? `<span class="badge bg-secondary">1/${totalPages} 페이지</span>` : ''}
                    </div>
                    <ul class="list-group list-group-flush" id="githubPocList">
            `;

            // 첫 페이지만 표시
            for (const poc of githubPocs.slice(0, pageSize)) {
                const verifiedBadge = poc.verified ? '<span class="badge bg-success ms-1" title="nomi-sec 검증됨">✓</span>' : '';
                html += `
                    <li class="list-group-item">
                        <div class="d-flex justify-content-between align-items-start">
                            <div style="flex: 1; min-width: 0;">
                                <a href="${poc.url}" target="_blank" class="fw-bold text-decoration-none">
                                    ${escapeHtml(poc.name)}
                                </a>${verifiedBadge}
                                <div class="small text-muted">
                                    <span class="me-2"><i class="bi bi-person"></i> ${escapeHtml(poc.owner)}</span>
                                    <span class="me-2"><i class="bi bi-star-fill text-warning"></i> ${poc.stars || 0}</span>
                                    <span><i class="bi bi-code-slash"></i> ${escapeHtml(poc.language || 'Unknown')}</span>
                                </div>
                                ${poc.description ? `<div class="small mt-1" style="overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;">${escapeHtml(poc.description)}</div>` : ''}
                            </div>
                            <a href="${poc.url}" target="_blank" class="btn btn-sm btn-outline-dark ms-2">
                                <i class="bi bi-box-arrow-up-right"></i>
                            </a>
                        </div>
                    </li>
                `;
            }

            html += `</ul>`;

            // 더보기 버튼 (5개 이상일 때만)
            if (githubPocs.length > pageSize) {
                html += `
                    <div class="card-footer py-2 text-center">
                        <button class="btn btn-sm btn-outline-dark" onclick="showMoreGithubPocs(1, ${pageSize})">
                            <i class="bi bi-chevron-down"></i> 더보기 (${githubPocs.length - pageSize}개 남음)
                        </button>
                    </div>
                `;
            }

            html += `</div>`;

            // 페이징 데이터 저장
            window.githubPocsData = githubPocs;
        }

        // Exploit-DB 목록 (페이징 처리)
        if (data.exploitdb && data.exploitdb.length > 0) {
            const exploitDbList = data.exploitdb;
            const pageSize = 5;
            const totalPages = Math.ceil(exploitDbList.length / pageSize);

            html += `
                <div class="card mb-3" id="exploitDbCard">
                    <div class="card-header py-2 bg-danger text-white d-flex justify-content-between align-items-center">
                        <span><i class="bi bi-shield-exclamation me-1"></i> Exploit-DB (${exploitDbList.length}개)</span>
                        ${exploitDbList.length > pageSize ? `<span class="badge bg-light text-dark">1/${totalPages} 페이지</span>` : ''}
                    </div>
                    <ul class="list-group list-group-flush" id="exploitDbList">
            `;

            // 첫 페이지만 표시
            for (const exp of exploitDbList.slice(0, pageSize)) {
                const downloadUrl = exp.download_url || `https://www.exploit-db.com/download/${exp.edb_id}`;
                const rawUrl = exp.raw_url || `https://www.exploit-db.com/raw/${exp.edb_id}`;

                html += `
                    <li class="list-group-item">
                        <div class="d-flex justify-content-between align-items-start">
                            <div style="flex: 1; min-width: 0;">
                                <a href="${exp.url}" target="_blank" class="fw-bold text-decoration-none">
                                    ${escapeHtml(exp.name)}
                                </a>
                                <div class="small text-muted mt-1">
                                    <span class="badge bg-secondary me-1">${exp.platform || 'Multi'}</span>
                                    <span class="badge bg-info me-1">${exp.type || 'Exploit'}</span>
                                    <span>EDB-ID: ${exp.edb_id}</span>
                                    ${exp.date_published ? `<span class="ms-2 text-muted">${exp.date_published}</span>` : ''}
                                </div>
                            </div>
                            <div class="btn-group btn-group-sm ms-2" style="flex-shrink: 0;">
                                <a href="${exp.url}" target="_blank" class="btn btn-outline-secondary" title="페이지 보기">
                                    <i class="bi bi-box-arrow-up-right"></i>
                                </a>
                                <a href="${rawUrl}" target="_blank" class="btn btn-outline-info" title="코드 보기">
                                    <i class="bi bi-code-slash"></i>
                                </a>
                                <a href="${downloadUrl}" target="_blank" class="btn btn-outline-danger" title="다운로드">
                                    <i class="bi bi-download"></i>
                                </a>
                            </div>
                        </div>
                    </li>
                `;
            }

            html += `</ul>`;

            // 더보기 버튼
            if (exploitDbList.length > pageSize) {
                html += `
                    <div class="card-footer py-2 text-center">
                        <button class="btn btn-sm btn-outline-danger" onclick="showMoreExploitDb(1, ${pageSize})">
                            <i class="bi bi-chevron-down"></i> 더보기 (${exploitDbList.length - pageSize}개 남음)
                        </button>
                    </div>
                `;
            }

            html += `</div>`;

            // 페이징 데이터 저장
            window.exploitDbData = exploitDbList;
        }

        pocContent.innerHTML = html;

    } catch (error) {
        pocContent.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-1"></i>
                PoC 정보 조회 실패: ${error.message}
            </div>
        `;
    }
}

async function executePocDryRun() {
    if (!currentPocCveId) return;

    const targetHost = document.getElementById('pocTargetHost')?.value;
    const targetPort = parseInt(document.getElementById('pocTargetPort')?.value) || 80;
    const pocType = document.getElementById('pocType')?.value || 'nmap_vuln';
    const pocUrl = document.getElementById('pocUrl')?.value || '';

    if (!targetHost) {
        showToast('타겟 호스트를 선택하세요', 'warning');
        return;
    }

    try {
        const result = await apiCall('/api/remote/exploit/execute', {
            method: 'POST',
            body: JSON.stringify({
                target_host: targetHost,
                target_port: targetPort,
                poc_type: pocType,
                poc_url: pocUrl,
                cve_id: currentPocCveId,
                dry_run: true
            })
        });

        // 결과 표시
        const resultHtml = `
            <div class="card border-success mt-3" id="pocResult">
                <div class="card-header py-2 bg-dark text-white d-flex justify-content-between align-items-center">
                    <span>
                        <i class="bi bi-terminal me-1"></i> Exploit 실행 스크립트 (Dry Run)
                    </span>
                    <button class="btn btn-sm btn-outline-light" onclick="copyToClipboard('pocResultCode')">
                        <i class="bi bi-clipboard"></i> 복사
                    </button>
                </div>
                <div class="card-body">
                    ${result.description ? `<div class="alert alert-info py-2 mb-3"><i class="bi bi-info-circle me-1"></i> ${escapeHtml(result.description)}</div>` : ''}
                    <pre class="bg-dark text-light p-3 rounded mb-0" id="pocResultCode" style="font-size: 11px; overflow-x: auto; max-height: 400px;">
${escapeHtml(result.command)}</pre>
                    <div class="mt-3 border-top pt-2">
                        <small class="text-danger fw-bold">
                            <i class="bi bi-exclamation-triangle-fill me-1"></i>
                            권한 없는 시스템에 대한 공격은 불법입니다. 반드시 승인된 테스트 환경에서만 사용하세요.
                        </small>
                    </div>
                </div>
            </div>
        `;

        // 이전 결과 제거
        const oldResult = document.getElementById('pocResult');
        if (oldResult) oldResult.remove();

        document.getElementById('pocContent').insertAdjacentHTML('beforeend', resultHtml);
        showToast('Exploit 스크립트 생성 완료!', 'success');

    } catch (error) {
        showToast(`Exploit 생성 실패: ${error.message}`, 'error');
    }
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const text = element.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('클립보드에 복사되었습니다!', 'success');
    }).catch(err => {
        showToast('복사 실패', 'error');
    });
}

// GitHub PoC 더보기 함수
function showMoreGithubPocs(currentPage, pageSize) {
    if (!window.githubPocsData) return;

    const nextPage = currentPage + 1;
    const startIdx = currentPage * pageSize;
    const endIdx = Math.min(startIdx + pageSize, window.githubPocsData.length);
    const totalPages = Math.ceil(window.githubPocsData.length / pageSize);

    const listEl = document.getElementById('githubPocList');
    const cardEl = document.getElementById('githubPocCard');

    // 다음 페이지 아이템 추가
    for (let i = startIdx; i < endIdx; i++) {
        const poc = window.githubPocsData[i];
        const verifiedBadge = poc.verified ? '<span class="badge bg-success ms-1" title="nomi-sec 검증됨">✓</span>' : '';

        const itemHtml = `
            <li class="list-group-item">
                <div class="d-flex justify-content-between align-items-start">
                    <div style="flex: 1; min-width: 0;">
                        <a href="${poc.url}" target="_blank" class="fw-bold text-decoration-none">
                            ${escapeHtml(poc.name)}
                        </a>${verifiedBadge}
                        <div class="small text-muted">
                            <span class="me-2"><i class="bi bi-person"></i> ${escapeHtml(poc.owner)}</span>
                            <span class="me-2"><i class="bi bi-star-fill text-warning"></i> ${poc.stars || 0}</span>
                            <span><i class="bi bi-code-slash"></i> ${escapeHtml(poc.language || 'Unknown')}</span>
                        </div>
                        ${poc.description ? `<div class="small mt-1" style="overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;">${escapeHtml(poc.description)}</div>` : ''}
                    </div>
                    <a href="${poc.url}" target="_blank" class="btn btn-sm btn-outline-dark ms-2">
                        <i class="bi bi-box-arrow-up-right"></i>
                    </a>
                </div>
            </li>
        `;
        listEl.insertAdjacentHTML('beforeend', itemHtml);
    }

    // 헤더의 페이지 표시 업데이트
    const headerBadge = cardEl.querySelector('.card-header .badge');
    if (headerBadge) {
        headerBadge.textContent = `${nextPage}/${totalPages} 페이지`;
    }

    // 더보기 버튼 업데이트
    const footer = cardEl.querySelector('.card-footer');
    if (endIdx >= window.githubPocsData.length) {
        // 모두 표시됨
        footer.remove();
    } else {
        const remaining = window.githubPocsData.length - endIdx;
        footer.innerHTML = `
            <button class="btn btn-sm btn-outline-dark" onclick="showMoreGithubPocs(${nextPage}, ${pageSize})">
                <i class="bi bi-chevron-down"></i> 더보기 (${remaining}개 남음)
            </button>
        `;
    }
}

// Exploit-DB 더보기 함수
function showMoreExploitDb(currentPage, pageSize) {
    if (!window.exploitDbData) return;

    const nextPage = currentPage + 1;
    const startIdx = currentPage * pageSize;
    const endIdx = Math.min(startIdx + pageSize, window.exploitDbData.length);
    const totalPages = Math.ceil(window.exploitDbData.length / pageSize);

    const listEl = document.getElementById('exploitDbList');
    const cardEl = document.getElementById('exploitDbCard');

    // 다음 페이지 아이템 추가
    for (let i = startIdx; i < endIdx; i++) {
        const exp = window.exploitDbData[i];
        const downloadUrl = exp.download_url || `https://www.exploit-db.com/download/${exp.edb_id}`;
        const rawUrl = exp.raw_url || `https://www.exploit-db.com/raw/${exp.edb_id}`;

        const itemHtml = `
            <li class="list-group-item">
                <div class="d-flex justify-content-between align-items-start">
                    <div style="flex: 1; min-width: 0;">
                        <a href="${exp.url}" target="_blank" class="fw-bold text-decoration-none">
                            ${escapeHtml(exp.name)}
                        </a>
                        <div class="small text-muted mt-1">
                            <span class="badge bg-secondary me-1">${exp.platform || 'Multi'}</span>
                            <span class="badge bg-info me-1">${exp.type || 'Exploit'}</span>
                            <span>EDB-ID: ${exp.edb_id}</span>
                            ${exp.date_published ? `<span class="ms-2 text-muted">${exp.date_published}</span>` : ''}
                        </div>
                    </div>
                    <div class="btn-group btn-group-sm ms-2" style="flex-shrink: 0;">
                        <a href="${exp.url}" target="_blank" class="btn btn-outline-secondary" title="페이지 보기">
                            <i class="bi bi-box-arrow-up-right"></i>
                        </a>
                        <a href="${rawUrl}" target="_blank" class="btn btn-outline-info" title="코드 보기">
                            <i class="bi bi-code-slash"></i>
                        </a>
                        <a href="${downloadUrl}" target="_blank" class="btn btn-outline-danger" title="다운로드">
                            <i class="bi bi-download"></i>
                        </a>
                    </div>
                </div>
            </li>
        `;
        listEl.insertAdjacentHTML('beforeend', itemHtml);
    }

    // 헤더의 페이지 표시 업데이트
    const headerBadge = cardEl.querySelector('.card-header .badge');
    if (headerBadge) {
        headerBadge.textContent = `${nextPage}/${totalPages} 페이지`;
    }

    // 더보기 버튼 업데이트
    const footer = cardEl.querySelector('.card-footer');
    if (endIdx >= window.exploitDbData.length) {
        // 모두 표시됨
        footer.remove();
    } else {
        const remaining = window.exploitDbData.length - endIdx;
        footer.innerHTML = `
            <button class="btn btn-sm btn-outline-danger" onclick="showMoreExploitDb(${nextPage}, ${pageSize})">
                <i class="bi bi-chevron-down"></i> 더보기 (${remaining}개 남음)
            </button>
        `;
    }
}

window.downloadNvdRange = downloadNvdRange;
window.showNvdManager = showNvdManager;
window.loadNvdRecords = loadNvdRecords;
window.deleteNvdYear = deleteNvdYear;
window.searchPoc = searchPoc;
window.showPocModal = showPocModal;
window.executePocDryRun = executePocDryRun;
window.copyToClipboard = copyToClipboard;
window.showMoreGithubPocs = showMoreGithubPocs;
window.showMoreExploitDb = showMoreExploitDb;
window.scanAllPoCs = scanAllPoCs;
