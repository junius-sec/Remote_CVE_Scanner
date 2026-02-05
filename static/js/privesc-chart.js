// Privilege Escalation / Unauthorized Visualization
// 더 직관적인 트리맵 + 테이블 형식

let currentRiskMode = 'privesc';
let currentCveSort = 'all';
let currentSankeyDensity = 'compact';  // 고정
let currentCveList = [];
let currentSummary = null;
let currentModeLabel = null;
let currentCategoryCves = {};  // 카테고리별 CVE ID 목록
let privescChartRendered = false;  // 렌더링 여부 추적

async function renderPrivescChart(force = false) {
    const container = document.getElementById('privescChart');
    if (!container) return;

    // 접혀있으면 렌더링 스킵 (force가 아닐 때)
    const collapseBody = document.getElementById('privescChartBody');
    if (!force && collapseBody && !collapseBody.classList.contains('show')) {
        privescChartRendered = false;
        return;
    }

    try {
        const params = new URLSearchParams();
        if (window.currentScanId) {
            params.append('scan_id', window.currentScanId);
        }

        params.append('mode', currentRiskMode);

        const response = await fetch(`/api/privesc-paths?${params}`);
        const data = await response.json();

        // 데이터 없음
        if (!data.summary || data.summary.total === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-5">
                    <h5 class="mt-3">${data.mode_label || '권한 상승'} CVE 없음</h5>
                    <p class="small">${data.mode_label || '권한 상승'} 관련 취약점이 발견되지 않았습니다</p>
                </div>
            `;
            return;
        }

        // 컨테이너 초기화
        container.innerHTML = '';

        // 레이아웃: 왼쪽 Sankey + 오른쪽 테이블
        const wrapper = document.createElement('div');
        wrapper.style.cssText = 'display: flex; gap: 16px; height: 100%;';

        // 왼쪽: Sankey
        const leftPanel = document.createElement('div');
        leftPanel.style.cssText = 'flex: 1; min-width: 0;';
        leftPanel.id = 'privescSankey';

        // 오른쪽: 상위 CVE 테이블
        const rightPanel = document.createElement('div');
        rightPanel.style.cssText = 'width: 280px; overflow-y: auto; font-size: 11px;';
        currentCveList = data.top_cves || [];
        currentSummary = data.summary || {};
        currentModeLabel = data.mode_label || '권한 상승';

        // 카테고리별 CVE ID 목록 구축
        currentCategoryCves = {};
        currentCveList.forEach(cve => {
            const cat = cve.category || 'other';
            if (!currentCategoryCves[cat]) {
                currentCategoryCves[cat] = [];
            }
            currentCategoryCves[cat].push(cve.cve_id);
        });

        renderCveTable(rightPanel);

        wrapper.appendChild(leftPanel);
        wrapper.appendChild(rightPanel);
        container.appendChild(wrapper);

        // Sankey 렌더링
        renderSankey('privescSankey', data);

    } catch (error) {
        console.error('Error rendering privesc chart:', error);
        container.innerHTML = `
            <div class="text-center text-muted py-5">
                <h5 class="mt-3">로드 실패</h5>
                <p class="small">${error.message}</p>
            </div>
        `;
    }
}

function createCveTable(topCves, summary, modeLabel) {
    if (!topCves || topCves.length === 0) {
        return '<div class="text-muted text-center py-3">CVE 없음</div>';
    }
    const titleLabel = modeLabel || '권한 상승';
    const totalCount = topCves.length;

    // 요약 헤더
    let html = `
        <div style="padding: 8px 0; border-bottom: 1px solid #e8e8ed; margin-bottom: 8px;">
            <div style="font-weight: 600; font-size: 12px; color: #1d1d1f; margin-bottom: 6px;">
                ${titleLabel} CVE: ${summary.total}개
            </div>
            <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                ${summary.critical > 0 ? `<span class="badge bg-danger">${summary.critical} Critical</span>` : ''}
                ${summary.high > 0 ? `<span class="badge bg-warning">${summary.high} High</span>` : ''}
                ${summary.kev_count > 0 ? `<span class="badge bg-dark">${summary.kev_count} KEV</span>` : ''}
                ${summary.running_count > 0 ? `<span class="badge bg-info">${summary.running_count} Running</span>` : ''}
            </div>
            <div style="display: flex; gap: 6px; margin-top: 8px; flex-wrap: wrap;">
                <button type="button" class="btn btn-outline-secondary btn-xs" data-cve-sort="all">
                    전체 (${totalCount})
                </button>
                <button type="button" class="btn btn-outline-secondary btn-xs" data-cve-sort="critical">
                    Critical
                </button>
                <button type="button" class="btn btn-outline-secondary btn-xs" data-cve-sort="high">
                    High
                </button>
                <button type="button" class="btn btn-outline-secondary btn-xs" data-cve-sort="running">
                    Running
                </button>
            </div>
        </div>
    `;

    // CVE 목록
    html += '<div style="display: flex; flex-direction: column; gap: 6px;">';

    topCves.forEach(cve => {
        const cvssColor = getCvssColor(cve.cvss);
        const badges = [];
        if (cve.is_kev) badges.push('<span class="badge bg-dark" style="font-size: 9px;">KEV</span>');
        if (cve.is_running) badges.push('<span class="badge bg-info" style="font-size: 9px;">RUN</span>');

        html += `
            <div style="padding: 6px 8px; background: #f5f5f7; border-radius: 6px; cursor: pointer;"
                 onclick="applyRiskCveFilter('${cve.cve_id}')">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 500; color: #1d1d1f;">${cve.cve_id}</span>
                    <span style="background: ${cvssColor}; color: white; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 600;">
                        ${cve.cvss?.toFixed(1) || 'N/A'}
                    </span>
                </div>
                <div style="color: #86868b; font-size: 10px; margin-top: 2px;">
                    ${cve.package} ${badges.length > 0 ? badges.join(' ') : ''}
                </div>
            </div>
        `;
    });

    html += '</div>';
    return html;
}

function getCveSortList(cves, sortMode) {
    let filtered = cves.slice();
    if (sortMode === 'critical') {
        filtered = filtered.filter(cve => (cve.cvss || 0) >= 9.0);
    } else if (sortMode === 'high') {
        filtered = filtered.filter(cve => {
            const score = cve.cvss || 0;
            return score >= 7.0 && score < 9.0;
        });
    } else if (sortMode === 'running') {
        filtered = filtered.filter(cve => cve.is_running);
    }

    filtered.sort((a, b) => {
        const scoreDiff = (b.cvss || 0) - (a.cvss || 0);
        if (scoreDiff !== 0) return scoreDiff;
        const runDiff = (b.is_running ? 1 : 0) - (a.is_running ? 1 : 0);
        if (runDiff !== 0) return runDiff;
        return (a.cve_id || '').localeCompare(b.cve_id || '');
    });

    return filtered;
}

function renderCveTable(container) {
    if (!container) return;
    const list = getCveSortList(currentCveList, currentCveSort);
    container.innerHTML = createCveTable(list, currentSummary, currentModeLabel);
    bindCveSortButtons(container);
}

function bindCveSortButtons(container) {
    container.querySelectorAll('button[data-cve-sort]').forEach(btn => {
        const mode = btn.dataset.cveSort;
        const isActive = mode === currentCveSort;
        btn.classList.toggle('btn-secondary', isActive);
        btn.classList.toggle('btn-outline-secondary', !isActive);
        btn.addEventListener('click', function() {
            currentCveSort = this.dataset.cveSort;
            renderCveTable(container);
        });
    });
}

function renderSankey(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container || !data.packages || data.packages.length === 0) {
        container.innerHTML = '<div class="text-center text-muted py-5">패키지 데이터 없음</div>';
        return;
    }

    const rootLabel = data.root_label || '권한 상승 취약점';
    const limits = getSankeyLimits(currentSankeyDensity);
    const packagesForSankey = limits.packages ? data.packages.slice(0, limits.packages) : data.packages;
    const packageNames = new Set(packagesForSankey.map(pkg => pkg.name));
    let cvesForSankey = data.top_cves.filter(cve => packageNames.has(cve.package));
    if (limits.cves) {
        cvesForSankey = cvesForSankey.slice(0, limits.cves);
    }
    const categoryCounts = buildCategoryCounts(data.categories || []);
    const categoryLabelMap = new Map();
    (data.categories || []).forEach(cat => {
        const label = formatCategoryLabel(cat.label, categoryCounts[cat.id] || 0);
        categoryLabelMap.set(cat.id, label);
    });

    const labels = [rootLabel];
    const nodeColors = ['#e9ecef'];
    const nodeMeta = [{ type: 'root', id: 'root' }];
    const labelToMeta = new Map();
    labelToMeta.set(rootLabel, nodeMeta[0]);

    const nodeIndex = new Map();
    nodeIndex.set(rootLabel, 0);

    data.categories.forEach(cat => {
        const label = categoryLabelMap.get(cat.id) || formatCategoryLabel(cat.label, categoryCounts[cat.id] || 0);
        if (nodeIndex.has(label)) return;
        nodeIndex.set(label, labels.length);
        labels.push(label);
        nodeColors.push(getCategoryColor(cat.id));
        const meta = { type: 'category', id: cat.id, label: cat.label };
        nodeMeta.push(meta);
        labelToMeta.set(label, meta);
    });

    packagesForSankey.forEach(pkg => {
        if (nodeIndex.has(pkg.name)) return;
        nodeIndex.set(pkg.name, labels.length);
        labels.push(pkg.name);
        nodeColors.push(getCvssColor(pkg.max_cvss));
        const meta = { type: 'package', id: pkg.name };
        nodeMeta.push(meta);
        labelToMeta.set(pkg.name, meta);
    });

    cvesForSankey.forEach(cve => {
        if (nodeIndex.has(cve.cve_id)) return;
        nodeIndex.set(cve.cve_id, labels.length);
        labels.push(cve.cve_id);
        nodeColors.push(getCvssColor(cve.cvss));
        const meta = { type: 'cve', id: cve.cve_id };
        nodeMeta.push(meta);
        labelToMeta.set(cve.cve_id, meta);
    });

    const sources = [];
    const targets = [];
    const values = [];
    const linkColors = [];

    data.categories.forEach(cat => {
        const label = categoryLabelMap.get(cat.id) || formatCategoryLabel(cat.label, categoryCounts[cat.id] || 0);
        sources.push(nodeIndex.get(rootLabel));
        targets.push(nodeIndex.get(label));
        values.push(cat.count);
        linkColors.push('rgba(108,117,125,0.25)');
    });

    packagesForSankey.forEach(pkg => {
        const catId = pkg.category || 'other';
        const catLabel = categoryLabelMap.get(catId) || formatCategoryLabel(getCategoryLabel(catId), categoryCounts[catId] || 0);
        if (!nodeIndex.has(catLabel)) {
            nodeIndex.set(catLabel, labels.length);
            labels.push(catLabel);
            nodeColors.push(getCategoryColor(catId));
            const meta = { type: 'category', id: catId, label: getCategoryLabel(catId) };
            nodeMeta.push(meta);
            labelToMeta.set(catLabel, meta);
        }
        sources.push(nodeIndex.get(catLabel));
        targets.push(nodeIndex.get(pkg.name));
        values.push(pkg.count);
        linkColors.push('rgba(13,110,253,0.22)');
    });

    cvesForSankey.forEach(cve => {
        if (!nodeIndex.has(cve.package) || !nodeIndex.has(cve.cve_id)) return;
        sources.push(nodeIndex.get(cve.package));
        targets.push(nodeIndex.get(cve.cve_id));
        values.push(1);
        linkColors.push('rgba(220,53,69,0.2)');
    });

    const sankeyData = [{
        type: 'sankey',
        arrangement: 'snap',
        node: {
            label: labels,
            color: nodeColors,
            pad: 12,
            thickness: 14,
            line: { color: 'rgba(255,255,255,0.7)', width: 0.5 },
            hoverinfo: 'none'
        },
        link: {
            source: sources,
            target: targets,
            value: values,
            color: linkColors,
            hoverinfo: 'none'
        },
        textfont: { size: 10 }
    }];

    const fontSize = currentSankeyDensity === 'full' ? 9 : (currentSankeyDensity === 'compact' ? 11 : 10);
    const layout = {
        margin: { l: 4, r: 4, t: 4, b: 4 },
        paper_bgcolor: 'rgba(0,0,0,0)',
        font: {
            family: '-apple-system, BlinkMacSystemFont, sans-serif',
            size: fontSize
        },
        hoverlabel: { namelength: 0 }
    };

    const config = {
        responsive: true,
        displayModeBar: false,
        staticPlot: false,
        scrollZoom: false,
        doubleClick: false
    };

    // 기존 차트 정리
    Plotly.purge(container);
    Plotly.newPlot(container, sankeyData, layout, config);

    if (typeof container.removeAllListeners === 'function') {
        container.removeAllListeners('plotly_click');
    }
    container.on('plotly_click', function(eventData) {
        const point = eventData?.points?.[0];
        if (!point) return;

        let meta = null;

        // 링크 클릭: source와 target이 객체로 존재
        if (point.source && point.target && typeof point.source === 'object') {
            // 링크 클릭 시 타겟 노드의 pointNumber로 메타데이터 직접 조회
            const targetPointNum = point.target.pointNumber;
            if (Number.isInteger(targetPointNum) && targetPointNum >= 0 && targetPointNum < nodeMeta.length) {
                meta = nodeMeta[targetPointNum];
            }
        } else if (point.label) {
            // 노드 직접 클릭: labels 배열에서 인덱스 찾기
            const idx = labels.indexOf(point.label);
            if (idx !== -1 && idx < nodeMeta.length) {
                meta = nodeMeta[idx];
            }
        }

        if (!meta || !meta.type || !meta.id) return;

        if (meta.type === 'package') {
            applyRiskPackageFilter(meta.id);
        } else if (meta.type === 'cve') {
            applyRiskCveFilter(meta.id);
        } else if (meta.type === 'category') {
            applyRiskCategoryFilter(meta.id);
        }
    });
}

function getCategoryColor(catId) {
    const colors = {
        'kernel': '#ff3b30',
        'suid': '#ff9500',
        'service': '#5856d6',
        'container': '#007aff',
        'network': '#0d6efd',
        'adjacent': '#6610f2',
        'local': '#198754',
        'physical': '#fd7e14',
        'other': '#8e8e93'
    };
    return colors[catId] || '#8e8e93';
}

function getCategoryLabel(catId) {
    const labels = {
        'kernel': 'Kernel',
        'suid': 'SUID/Sudo',
        'service': 'Service',
        'container': 'Container',
        'network': 'Network',
        'adjacent': 'Adjacent',
        'local': 'Local',
        'physical': 'Physical',
        'other': 'Other'
    };
    return labels[catId] || 'Other';
}

function getCvssColor(cvss) {
    if (!cvss) return '#8e8e93';
    if (cvss >= 9.0) return '#ff3b30';
    if (cvss >= 7.0) return '#ff9500';
    if (cvss >= 4.0) return '#ffcc00';
    return '#34c759';
}

function buildCategoryCounts(categories) {
    const counts = {};
    categories.forEach(cat => {
        counts[cat.id] = cat.count || 0;
    });
    return counts;
}

function formatCategoryLabel(label, count) {
    if (!count) return label;
    return `${label} (${count})`;
}

function getSankeyLimits(density) {
    if (density === 'compact') {
        return { packages: 8, cves: 16 };
    }
    if (density === 'full') {
        return { packages: 30, cves: 60 };
    }
    // normal
    return { packages: 15, cves: 30 };
}

function setRiskContext() {
    window.riskModeContext = currentRiskMode;
}

function applyRiskPackageFilter(packageName) {
    if (typeof applyPackageFilter !== 'function') return;
    setRiskContext();
    applyPackageFilter(packageName);
}

function applyRiskCveFilter(cveId) {
    if (typeof applyCveFilter !== 'function') return;
    setRiskContext();
    applyCveFilter(cveId);
}

function applyRiskCategoryFilter(categoryId) {
    if (typeof applyCategoryFilter !== 'function') return;
    setRiskContext();
    // 해당 카테고리의 CVE ID 목록 전달
    const cveIds = currentCategoryCves[categoryId] || [];
    applyCategoryFilter(categoryId, cveIds);
}

function setRiskMode(mode) {
    if (!mode || mode === currentRiskMode) return;
    currentRiskMode = mode;
    currentCveSort = 'all';
    updateRiskToggleUi();
    renderPrivescChart();
}

function updateRiskToggleUi() {
    const toggle = document.getElementById('riskModeToggle');
    if (!toggle) return;

    toggle.querySelectorAll('button[data-risk-mode]').forEach(btn => {
        const isActive = btn.dataset.riskMode === currentRiskMode;
        btn.classList.toggle('active', isActive);
        btn.classList.toggle('btn-secondary', isActive);
        btn.classList.toggle('btn-outline-secondary', !isActive);
    });
}

function initRiskToggle() {
    const toggle = document.getElementById('riskModeToggle');
    if (!toggle) return;

    toggle.querySelectorAll('button[data-risk-mode]').forEach(btn => {
        btn.addEventListener('click', function() {
            setRiskMode(this.dataset.riskMode);
        });
    });
    updateRiskToggleUi();
}

function initPrivescCollapse() {
    const collapseEl = document.getElementById('privescChartBody');
    const icon = document.getElementById('privescCollapseIcon');
    if (!collapseEl) return;

    // 펼쳐질 때 렌더링
    collapseEl.addEventListener('shown.bs.collapse', function() {
        if (icon) icon.className = 'bi bi-chevron-down me-1';
        if (!privescChartRendered) {
            renderPrivescChart(true);
            privescChartRendered = true;
        }
    });

    // 접힐 때 아이콘 변경 + 차트 정리
    collapseEl.addEventListener('hidden.bs.collapse', function() {
        if (icon) icon.className = 'bi bi-chevron-right me-1';
        const container = document.getElementById('privescChart');
        if (container && typeof Plotly !== 'undefined') {
            Plotly.purge(container);
        }
        privescChartRendered = false;
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        initRiskToggle();
        initPrivescCollapse();
    });
} else {
    initRiskToggle();
    initPrivescCollapse();
}

// Export
window.renderPrivescChart = renderPrivescChart;
window.applyRiskPackageFilter = applyRiskPackageFilter;
window.applyRiskCveFilter = applyRiskCveFilter;
window.applyRiskCategoryFilter = applyRiskCategoryFilter;
