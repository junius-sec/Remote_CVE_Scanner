"""PDF Report Generator for Vulnerability Scan Results"""
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.platypus.flowables import HRFlowable
from datetime import datetime
from typing import List, Dict, Optional
import io


class VulnerabilityPDFGenerator:
    """Generate professional PDF reports for vulnerability scans"""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()

    def _create_custom_styles(self):
        """Create custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2C3E50'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495E'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='SubHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#7F8C8D'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6
        ))

    def generate_report(
        self,
        host_info: Dict,
        dashboard_stats: Dict,
        findings: List[Dict],
        package_summary: Dict,
        scan_config: Optional[Dict] = None  # 신규: 스캔 설정 정보
    ) -> bytes:
        """Generate complete vulnerability report PDF
        
        Args:
            host_info: 호스트 정보
            dashboard_stats: 대시보드 통계
            findings: 취약점 목록
            package_summary: 패키지 요약
            scan_config: 스캔 설정 (preset, categories, remote 스캔 정보 등)
        """

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )

        # Container for PDF elements
        story = []

        # Title Page
        story.extend(self._create_title_page(host_info, scan_config))
        story.append(PageBreak())

        # Executive Summary
        story.extend(self._create_executive_summary(dashboard_stats, host_info, scan_config))
        story.append(Spacer(1, 0.3*inch))

        # Discovery Information (Remote scan only)
        if scan_config and scan_config.get('discovery_info'):
            story.extend(self._create_discovery_section(scan_config['discovery_info']))
            story.append(Spacer(1, 0.3*inch))

        # Vulnerability Statistics
        story.extend(self._create_statistics_section(dashboard_stats, package_summary))
        story.append(Spacer(1, 0.3*inch))

        # Risk Distribution
        story.extend(self._create_risk_distribution(findings))
        
        # Data Confidence Distribution (신규)
        story.extend(self._create_confidence_distribution(findings))
        story.append(PageBreak())

        # Detailed Findings
        story.extend(self._create_detailed_findings(findings))

        # Recommendations
        story.append(PageBreak())
        story.extend(self._create_recommendations(dashboard_stats))

        # Build PDF
        doc.build(story)
        buffer.seek(0)

        return buffer.getvalue()

    def _create_title_page(self, host_info: Dict, scan_config: Optional[Dict] = None) -> List:
        """Create report title page"""
        elements = []

        elements.append(Spacer(1, 2*inch))

        # Title
        title = Paragraph(
            "리눅스 시스템 취약점<br/>스캔 보고서",
            self.styles['CustomTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))

        # Host Information
        host_data = [
            ['호스트명', host_info.get('hostname', 'N/A')],
            ['IP 주소', host_info.get('ip_address', 'N/A')],
            ['운영체제', f"{host_info.get('os_type', 'N/A')} {host_info.get('os_version', '')}"],
            ['스캔 일시', datetime.now().strftime('%Y년 %m월 %d일 %H:%M:%S')]
        ]
        
        # Remote scan 정보 추가
        if scan_config:
            if scan_config.get('preset'):
                preset_names = {'fast': '빠른 스캔', 'standard': '표준 스캔', 'deep': '심층 스캔'}
                host_data.append(['스캔 모드', preset_names.get(scan_config['preset'], scan_config['preset'])])
            if scan_config.get('scan_type') == 'remote':
                host_data.append(['스캔 유형', '원격 스캔 (Agentless)'])
            if scan_config.get('categories'):
                host_data.append(['스캔 범위', ', '.join(scan_config['categories'])])

        host_table = Table(host_data, colWidths=[2*inch, 4*inch])
        host_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ECF0F1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2C3E50')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7'))
        ]))

        elements.append(host_table)
        elements.append(Spacer(1, 1*inch))

        # Warning notice
        warning = Paragraph(
            "<b>⚠️ 기밀 문서</b><br/>"
            "본 보고서는 시스템 보안 취약점 정보를 포함하고 있습니다.<br/>"
            "관계자 외 열람 및 배포를 금지합니다.",
            ParagraphStyle(
                'Warning',
                parent=self.styles['BodyText'],
                fontSize=9,
                textColor=colors.HexColor('#E74C3C'),
                alignment=TA_CENTER,
                borderColor=colors.HexColor('#E74C3C'),
                borderWidth=1,
                borderPadding=10
            )
        )
        elements.append(warning)

        return elements

    def _create_executive_summary(self, stats: Dict, host_info: Dict, scan_config: Optional[Dict] = None) -> List:
        """Create executive summary section"""
        elements = []

        elements.append(Paragraph("📊 요약", self.styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3498DB')))
        elements.append(Spacer(1, 0.2*inch))

        # Confidence 경고 추가
        confidence_warning = ""
        if scan_config and scan_config.get('overall_confidence') == 'low':
            confidence_warning = """
            <br/><br/>
            <font color="#E67E22">⚠️ <b>주의:</b> 본 스캔 결과는 바이너리 버전 추출 방식으로 수집되어 
            데이터 신뢰도가 낮을 수 있습니다. 패키지 매니저 기반 정보가 아니므로 
            결과 검토 시 주의가 필요합니다.</font>
            """

        summary_text = f"""
        <b>{host_info.get('hostname', 'N/A')}</b> 시스템에 대한 취약점 스캔 결과,
        총 <b>{stats.get('total_findings', 0)}개</b>의 취약점이 발견되었습니다.
        이 중 <b>{stats.get('high_risk_count', 0)}개</b>는 CVSS 7.0 이상의 고위험 취약점이며,
        <b>{stats.get('unauthorized_count', 0)}개</b>는 비인가 접근이 가능한 취약점입니다.
        <br/><br/>
        즉시 조치가 필요한 고위험 취약점에 대한 패치 적용을 권장합니다.
        {confidence_warning}
        """

        elements.append(Paragraph(summary_text, self.styles['BodyText']))
        elements.append(Spacer(1, 0.2*inch))

        return elements
    
    def _create_discovery_section(self, discovery_info: Dict) -> List:
        """Create discovery information section for remote scans"""
        elements = []

        elements.append(Paragraph("🔍 시스템 탐색 결과", self.styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#9B59B6')))
        elements.append(Spacer(1, 0.2*inch))

        discovery_data = [
            ['항목', '결과'],
            ['배포판 ID', discovery_info.get('distro_id', 'N/A')],
            ['패키지 매니저', discovery_info.get('pkg_manager', 'N/A')],
            ['아키텍처', discovery_info.get('arch', 'N/A')],
            ['커널 버전', discovery_info.get('kernel_version', 'N/A')],
            ['BusyBox 환경', '예' if discovery_info.get('is_busybox') else '아니오'],
            ['Systemd 사용', '예' if discovery_info.get('has_systemd') else '아니오'],
            ['탐색 신뢰도', discovery_info.get('confidence', 'N/A').upper()],
        ]

        discovery_table = Table(discovery_data, colWidths=[2.5*inch, 4*inch])
        discovery_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#9B59B6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#ECF0F1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8F9FA')])
        ]))

        elements.append(discovery_table)
        elements.append(Spacer(1, 0.2*inch))

        return elements

    def _create_statistics_section(self, stats: Dict, package_summary: Dict) -> List:
        """Create statistics overview section"""
        elements = []

        elements.append(Paragraph("📈 통계 개요", self.styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3498DB')))
        elements.append(Spacer(1, 0.2*inch))

        # Statistics table
        stats_data = [
            ['항목', '수량', '비고'],
            ['전체 취약점', str(stats.get('total_findings', 0)), ''],
            ['고위험 (CVSS ≥ 7.0)', str(stats.get('high_risk_count', 0)), '🔴 즉시 조치 필요'],
            ['비인가 접근 가능', str(stats.get('unauthorized_count', 0)), '⚠️ 우선 조치 권장'],
            ['취약 패키지 수', str(package_summary.get('total_packages', 0)), ''],
        ]

        stats_table = Table(stats_data, colWidths=[2.5*inch, 1.5*inch, 2.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498DB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ECF0F1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.white),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8F9FA')])
        ]))

        elements.append(stats_table)

        return elements

    def _create_risk_distribution(self, findings: List[Dict]) -> List:
        """Create risk level distribution"""
        elements = []

        elements.append(Paragraph("🎯 위험도별 분포", self.styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3498DB')))
        elements.append(Spacer(1, 0.2*inch))

        # Count by risk level
        risk_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0
        }

        for finding in findings:
            risk_level = finding.get('risk_level', 'unknown')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1

        risk_data = [
            ['위험도', 'CVSS 범위', '개수', '비율'],
            ['🔴 치명적 (Critical)', '9.0 - 10.0', str(risk_counts['critical']),
             f"{risk_counts['critical']/max(len(findings), 1)*100:.1f}%"],
            ['🟠 높음 (High)', '7.0 - 8.9', str(risk_counts['high']),
             f"{risk_counts['high']/max(len(findings), 1)*100:.1f}%"],
            ['🟡 보통 (Medium)', '4.0 - 6.9', str(risk_counts['medium']),
             f"{risk_counts['medium']/max(len(findings), 1)*100:.1f}%"],
            ['🟢 낮음 (Low)', '0.1 - 3.9', str(risk_counts['low']),
             f"{risk_counts['low']/max(len(findings), 1)*100:.1f}%"],
        ]

        risk_table = Table(risk_data, colWidths=[2*inch, 1.8*inch, 1.2*inch, 1.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8F9FA')])
        ]))

        elements.append(risk_table)

        return elements
    
    def _create_confidence_distribution(self, findings: List[Dict]) -> List:
        """Create data confidence distribution section"""
        elements = []

        # Confidence 필드가 있는지 확인
        has_confidence = any(f.get('data_confidence') for f in findings)
        if not has_confidence:
            return elements

        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph("📊 데이터 신뢰도 분포", self.styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#9B59B6')))
        elements.append(Spacer(1, 0.2*inch))

        # Count by confidence level
        confidence_counts = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0
        }

        for finding in findings:
            confidence = finding.get('data_confidence', 'unknown')
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1

        confidence_data = [
            ['신뢰도', '수집 방법', '개수', '비율'],
            ['🟢 높음 (High)', '패키지 매니저 (apk, dpkg, rpm, opkg)', 
             str(confidence_counts['high']),
             f"{confidence_counts['high']/max(len(findings), 1)*100:.1f}%"],
            ['🟡 보통 (Medium)', '바이너리 버전 추출', 
             str(confidence_counts['medium']),
             f"{confidence_counts['medium']/max(len(findings), 1)*100:.1f}%"],
            ['🔴 낮음 (Low)', '추정 또는 불확실', 
             str(confidence_counts['low']),
             f"{confidence_counts['low']/max(len(findings), 1)*100:.1f}%"],
        ]

        confidence_table = Table(confidence_data, colWidths=[1.5*inch, 2.8*inch, 1*inch, 1.2*inch])
        confidence_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#9B59B6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8F9FA')])
        ]))

        elements.append(confidence_table)

        # 낮은 신뢰도 비율이 높으면 경고
        low_ratio = confidence_counts['low'] / max(len(findings), 1)
        if low_ratio > 0.3:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph(
                f"<font color='#E67E22'>⚠️ 낮은 신뢰도 데이터가 {low_ratio*100:.1f}%를 차지합니다. "
                "결과 검토 시 주의가 필요합니다.</font>",
                self.styles['BodyText']
            ))

        return elements

    def _create_detailed_findings(self, findings: List[Dict]) -> List:
        """Create detailed findings table"""
        elements = []

        elements.append(Paragraph("🔍 상세 취약점 목록", self.styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3498DB')))
        elements.append(Spacer(1, 0.2*inch))

        # Sort by CVSS score (highest first)
        sorted_findings = sorted(
            findings,
            key=lambda x: x.get('cvss_score') or 0,
            reverse=True
        )

        # Limit to top 50 findings for PDF
        top_findings = sorted_findings[:50]
        
        # Confidence 필드가 있는지 확인
        has_confidence = any(f.get('data_confidence') for f in findings)

        if has_confidence:
            findings_data = [['패키지', '버전', 'CVE ID', 'CVSS', '위험도', '신뢰도', '수집']]
        else:
            findings_data = [['패키지', '버전', 'CVE ID', 'CVSS', '위험도']]

        for finding in top_findings:
            risk_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(finding.get('risk_level', 'unknown'), '⚪')
            
            confidence_emoji = {
                'high': '🟢',
                'medium': '🟡',
                'low': '🔴'
            }.get(finding.get('data_confidence', ''), '⚪')
            
            collector_abbr = {
                'pkg': 'PKG',
                'binary': 'BIN',
                'kernel': 'KNL'
            }.get(finding.get('collector_mode', ''), '')

            row = [
                finding.get('package_name', 'N/A')[:18],
                finding.get('package_version', 'N/A')[:12],
                finding.get('cve_id', 'N/A'),
                f"{finding.get('cvss_score', 0):.1f}" if finding.get('cvss_score') else 'N/A',
                f"{risk_emoji} {finding.get('risk_level', 'unknown').title()}"
            ]
            
            if has_confidence:
                row.extend([
                    f"{confidence_emoji}",
                    collector_abbr
                ])
            
            findings_data.append(row)

        if has_confidence:
            findings_table = Table(findings_data, colWidths=[1.3*inch, 1.0*inch, 1.3*inch, 0.6*inch, 1.2*inch, 0.5*inch, 0.5*inch])
        else:
            findings_table = Table(findings_data, colWidths=[1.5*inch, 1.3*inch, 1.5*inch, 0.8*inch, 1.4*inch])
        
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E74C3C')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (3, 1), (3, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFFFFF'), colors.HexColor('#FAFAFA')])
        ]))

        elements.append(findings_table)

        if len(sorted_findings) > 50:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph(
                f"<i>* 전체 {len(sorted_findings)}개 취약점 중 상위 50개만 표시됨</i>",
                self.styles['BodyText']
            ))
        
        # 범례 추가 (confidence 있는 경우)
        if has_confidence:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph(
                "<i>신뢰도: 🟢높음(패키지매니저) 🟡보통(바이너리) 🔴낮음(추정) | "
                "수집: PKG=패키지매니저 BIN=바이너리 KNL=커널</i>",
                ParagraphStyle('Legend', parent=self.styles['BodyText'], fontSize=7, textColor=colors.grey)
            ))

        return elements

    def _create_recommendations(self, stats: Dict) -> List:
        """Create recommendations section"""
        elements = []

        elements.append(Paragraph("💡 권장 조치사항", self.styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#27AE60')))
        elements.append(Spacer(1, 0.2*inch))

        recommendations = [
            "<b>1. 즉시 조치 (24시간 이내)</b>",
            "   • CVSS 9.0 이상 치명적 취약점 패치 적용",
            "   • 비인가 접근 가능 취약점 우선 처리",
            "   • 인터넷 노출 서비스의 고위험 취약점 패치",
            "",
            "<b>2. 단기 조치 (1주일 이내)</b>",
            "   • CVSS 7.0 이상 고위험 취약점 패치",
            "   • 중요 시스템 패키지 업데이트",
            "   • 불필요한 서비스 중단 검토",
            "",
            "<b>3. 중기 조치 (1개월 이내)</b>",
            "   • CVSS 4.0 이상 보통 위험 취약점 패치",
            "   • 정기 스캔 일정 수립 (주간/월간)",
            "   • 패치 관리 프로세스 확립",
            "",
            "<b>4. 장기 대책</b>",
            "   • 자동 보안 업데이트 설정 검토",
            "   • 취약점 모니터링 체계 구축",
            "   • 보안 정책 및 가이드라인 수립",
            "   • 정기적인 보안 교육 실시",
            "",
            "<b>⚠️ 주의사항</b>",
            "   • 패치 적용 전 반드시 백업 수행",
            "   • 테스트 환경에서 먼저 검증",
            "   • 의존성 충돌 가능성 확인",
            "   • 서비스 중단 시간 계획 수립"
        ]

        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles['BodyText']))

        elements.append(Spacer(1, 0.3*inch))

        # Footer
        footer = Paragraph(
            f"<i>보고서 생성 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i><br/>"
            "<i>Linux CVE 취약점 대시보드 v2.0 (Agentless Remote Scan)</i>",
            ParagraphStyle(
                'Footer',
                parent=self.styles['BodyText'],
                fontSize=8,
                textColor=colors.grey,
                alignment=TA_CENTER
            )
        )
        elements.append(footer)

        return elements
