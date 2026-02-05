// Bubble chart visualization (CVSS x EPSS x CVE count)
async function renderBubbleChart() {
    const container = document.getElementById('bubbleChart');
    if (!container) {
        return;
    }

    try {
        const params = new URLSearchParams();

        if (currentFilters.cvss_min) params.append('cvss_min', currentFilters.cvss_min);
        if (currentFilters.epss_min !== null && currentFilters.epss_min !== undefined) {
            params.append('epss_min', currentFilters.epss_min);
        }
        if (currentFilters.unauthorized_only) params.append('unauthorized_only', 'true');

        if (window.currentScanId) {
            params.append('scan_id', window.currentScanId);
        }

        const response = await fetch(`/api/bubble?${params}`);
        const data = await response.json();

        if (!data.points || data.points.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="bi bi-info-circle" style="font-size: 3rem;"></i>
                    <h5 class="mt-3">취약점 데이터가 없습니다</h5>
                    <p>스캔을 실행하면 결과가 여기에 표시됩니다</p>
                </div>
            `;
            return;
        }

        const points = data.points;
        const labels = points.map(p => p.package);
        const cvssValues = points.map(p => p.cvss_max || 0);
        const epssValues = points.map(p => p.epss_max || 0);
        const counts = points.map(p => p.cve_count || 0);
        const epssDisplay = points.map(p => p.epss_max ? `${(p.epss_max * 100).toFixed(2)}%` : '-');
        const customData = points.map((p, index) => [
            epssDisplay[index],
            p.cve_count || 0,
            p.kev_count || 0,
            p.running_count || 0,
            p.listening_count || 0
        ]);

        const maxCount = Math.max(...counts, 1);
        const sizeref = (2.0 * maxCount) / (60 ** 2);

        const trace = {
            x: cvssValues,
            y: epssValues,
            text: labels,
            customdata: customData,
            mode: 'markers',
            marker: {
                size: counts,
                sizemode: 'area',
                sizeref: sizeref,
                sizemin: 8,
                color: cvssValues,
                cmin: 0,
                cmax: 10,
                colorscale: [
                    [0.0, '#6c757d'],
                    [0.4, '#ffc107'],
                    [0.7, '#fd7e14'],
                    [0.9, '#dc3545'],
                    [1.0, '#8b0000']
                ],
                colorbar: {
                    title: 'CVSS'
                },
                line: {
                    width: 1,
                    color: 'rgba(255,255,255,0.6)'
                },
                opacity: 0.85
            },
            hovertemplate:
                '<b>%{text}</b><br>' +
                'CVSS (max): %{x:.1f}<br>' +
                'EPSS (max): %{customdata[0]}<br>' +
                'CVE 개수: %{customdata[1]}<br>' +
                'KEV: %{customdata[2]}<br>' +
                '실행중: %{customdata[3]}<br>' +
                '리스닝: %{customdata[4]}' +
                '<extra></extra>'
        };

        const layout = {
            margin: { t: 20, r: 20, b: 50, l: 60 },
            xaxis: {
                title: 'CVSS (max)',
                range: [0, 10],
                gridcolor: '#e9ecef'
            },
            yaxis: {
                title: 'EPSS (max)',
                range: [0, 1],
                tickformat: '.0%',
                gridcolor: '#e9ecef'
            },
            plot_bgcolor: '#f8f9fa',
            paper_bgcolor: '#f8f9fa',
            hovermode: 'closest'
        };

        const config = {
            responsive: true,
            displayModeBar: false
        };

        await Plotly.newPlot(container, [trace], layout, config);

        container.on('plotly_click', function(eventData) {
            const pkgName = eventData?.points?.[0]?.text;
            if (pkgName) {
                if (typeof applyPackageFilter === 'function') {
                    applyPackageFilter(pkgName);
                }
            }
        });

        await renderSeverityChart();
    } catch (error) {
        console.error('Error rendering bubble chart:', error);
        container.innerHTML = `
            <div class="text-center text-danger py-5">
                <i class="bi bi-exclamation-triangle" style="font-size: 3rem;"></i>
                <h5 class="mt-3">버블 차트 로딩 실패</h5>
                <p>${error.message}</p>
            </div>
        `;
        await renderSeverityChart();
    }
}

async function renderSeverityChart() {
    const container = document.getElementById('severityChart');
    if (!container) {
        return;
    }

    try {
        const params = new URLSearchParams();
        params.append('limit', '1000');

        if (currentFilters.cvss_min) params.append('cvss_min', currentFilters.cvss_min);
        if (currentFilters.epss_min !== null && currentFilters.epss_min !== undefined) {
            params.append('epss_min', currentFilters.epss_min);
        }
        if (currentFilters.impact_filter) params.append('impact_filter', currentFilters.impact_filter);
        if (currentFilters.kev_only) params.append('kev_only', 'true');
        if (currentFilters.unauthorized_only) params.append('unauthorized_only', 'true');
        if (currentFilters.no_user_interaction) params.append('no_user_interaction', 'true');
        if (currentFilters.package_name) params.append('package_name', currentFilters.package_name);
        if (currentFilters.cve_id) params.append('cve_id', currentFilters.cve_id);
        if (currentFilters.privesc_only) params.append('privesc_only', 'true');
        if (currentFilters.listening_only) params.append('listening_only', 'true');
        if (currentFilters.attack_vector) params.append('attack_vector', currentFilters.attack_vector);
        if (currentFilters.kernel_only) params.append('kernel_only', 'true');
        if (currentFilters.running_only) params.append('running_only', 'true');

        if (window.currentScanId) {
            params.append('scan_id', window.currentScanId);
        }

        const response = await fetch(`/api/findings?${params}`);
        const data = await response.json();
        const findings = data.items || data;

        if (!findings || findings.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="bi bi-info-circle" style="font-size: 3rem;"></i>
                    <h5 class="mt-3">취약점 데이터가 없습니다</h5>
                    <p>스캔을 실행하면 결과가 여기에 표시됩니다</p>
                </div>
            `;
            return;
        }

        const buckets = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            UNKNOWN: 0
        };

        findings.forEach(finding => {
            const severity = (finding.severity || '').toUpperCase();
            if (severity && buckets[severity] !== undefined) {
                buckets[severity] += 1;
                return;
            }
            const score = finding.cvss_score;
            if (score === null || score === undefined) {
                buckets.UNKNOWN += 1;
            } else if (score >= 9.0) {
                buckets.CRITICAL += 1;
            } else if (score >= 7.0) {
                buckets.HIGH += 1;
            } else if (score >= 4.0) {
                buckets.MEDIUM += 1;
            } else {
                buckets.LOW += 1;
            }
        });

        const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
        const values = labels.map(label => buckets[label]);
        const colors = ['#dc3545', '#fd7e14', '#ffc107', '#198754', '#6c757d'];

        const trace = {
            type: 'bar',
            x: values,
            y: labels,
            orientation: 'h',
            marker: {
                color: colors,
                line: { color: 'rgba(255,255,255,0.6)', width: 1 }
            },
            text: values.map(v => v.toString()),
            textposition: 'outside',
            hovertemplate: '%{y}: %{x}<extra></extra>'
        };

        const layout = {
            margin: { t: 10, r: 20, b: 40, l: 80 },
            xaxis: {
                title: '취약점 개수',
                gridcolor: '#e9ecef',
                zeroline: false
            },
            yaxis: {
                gridcolor: '#f1f3f5'
            },
            plot_bgcolor: '#f8f9fa',
            paper_bgcolor: '#f8f9fa'
        };

        const config = {
            responsive: true,
            displayModeBar: false
        };

        await Plotly.newPlot(container, [trace], layout, config);
    } catch (error) {
        console.error('Error rendering severity chart:', error);
        container.innerHTML = `
            <div class="text-center text-danger py-5">
                <i class="bi bi-exclamation-triangle" style="font-size: 3rem;"></i>
                <h5 class="mt-3">분포 차트 로딩 실패</h5>
                <p>${error.message}</p>
            </div>
        `;
    }
}
