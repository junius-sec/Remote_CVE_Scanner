from typing import List, Dict


class PackageScanner:
    """Package filtering and categorization for vulnerability scanning"""

    def __init__(self):
        pass

    def get_package_categories(self) -> Dict[str, List[str]]:
        """Get package categories for filtering"""
        return {
            "system": [
                "linux-image", "linux-headers", "kernel", "linux-firmware",
                "sudo", "systemd", "bash", "glibc", "libc6", "coreutils", "util-linux"
            ],
            "web": [
                "apache", "nginx", "httpd", "lighttpd", "apache2", "tomcat"
            ],
            "database": [
                "mysql", "mariadb", "postgresql", "mongodb", "redis", "sqlite"
            ],
            "programming": [
                "python3", "python2", "python", "php", "ruby", "nodejs", "node",
                "openjdk", "java", "perl", "gcc", "g++"
            ],
            "security": [
                "openssh", "ssh", "openssl", "libssl", "gnutls", "libgnutls",
                "krb5", "libkrb"
            ],
            "network": [
                "curl", "wget", "bind", "dnsmasq", "net-tools", "iproute2",
                "iptables", "nftables"
            ],
            "libraries": [
                "zlib", "libz", "bzip2", "xz-utils", "libarchive",
                "libpng", "libjpeg", "libwebp", "imagemagick", "ffmpeg",
                "libxml", "expat", "json-c", "libjson"
            ],
            "desktop": [
                "xorg", "x11", "mesa", "gtk", "qt", "webkit", "gnome", "kde"
            ]
        }

    def count_packages_by_category(self, packages: List[Dict]) -> Dict[str, int]:
        """Count packages in each category"""
        categories = self.get_package_categories()
        counts = {cat: 0 for cat in categories.keys()}
        counts["other"] = 0

        for pkg in packages:
            pkg_name_lower = pkg["name"].lower()
            matched = False

            for category, keywords in categories.items():
                for keyword in keywords:
                    if pkg_name_lower == keyword or pkg_name_lower.startswith(keyword + "-") or pkg_name_lower.startswith(keyword):
                        counts[category] += 1
                        matched = True
                        break
                if matched:
                    break

            if not matched:
                counts["other"] += 1

        return counts

    def filter_critical_packages(self, packages: List[Dict], selected_categories: List[str] = None) -> List[Dict]:
        """Filter packages by selected categories"""
        if not selected_categories or "all" in selected_categories:
            # Return all packages
            packages.sort(key=lambda x: x["name"])
            print(f"스캔 대상: 전체 {len(packages)}개 패키지 (필터링 없음)")
            return packages

        categories = self.get_package_categories()
        filtered = []
        seen = set()

        for pkg in packages:
            pkg_name_lower = pkg["name"].lower()

            for category in selected_categories:
                if category == "other":
                    # Check if package doesn't match any category
                    matched_any = False
                    for cat_keywords in categories.values():
                        for keyword in cat_keywords:
                            if pkg_name_lower == keyword or pkg_name_lower.startswith(keyword + "-") or pkg_name_lower.startswith(keyword):
                                matched_any = True
                                break
                        if matched_any:
                            break

                    if not matched_any and pkg_name_lower not in seen:
                        filtered.append(pkg)
                        seen.add(pkg_name_lower)
                        break
                elif category in categories:
                    for keyword in categories[category]:
                        if pkg_name_lower == keyword or pkg_name_lower.startswith(keyword + "-") or pkg_name_lower.startswith(keyword):
                            if pkg_name_lower not in seen:
                                filtered.append(pkg)
                                seen.add(pkg_name_lower)
                            break

        filtered.sort(key=lambda x: x["name"])
        print(f"스캔 대상: {len(filtered)}개 패키지 (카테고리: {', '.join(selected_categories)})")

        if len(filtered) > 0:
            print(f"패키지 목록 샘플 (처음 10개):")
            for i, pkg in enumerate(filtered[:10], 1):
                print(f"   {i}. {pkg['name']} ({pkg['version']})")

        return filtered
