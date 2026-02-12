# GitHub 업로드 가이드

## 1단계: 로컬 변경사항 커밋

```bash
# 현재 위치 확인
cd /home/user/바탕화면/dev

# 모든 파일 스테이징 (숨김 파일 포함)
git add -A

# 커밋
git commit -m "Initial commit: VulnScan v1.0.0

- 원격 SSH 스캔 기능
- NVD CVE 매칭 (1.1GB 캐시 포함)
- EPSS/KEV 통합
- 패키지 실행 시간 추적 (dpkg -L 기반)
- Docker 지원
- 웹 대시보드
- 사용 설명서 및 기술 문서"
```

## 2단계: GitHub 저장소 생성

### GitHub 웹사이트에서:

1. https://github.com 접속 및 로그인
2. 우측 상단 `+` 버튼 → `New repository` 클릭
3. 저장소 정보 입력:
   - Repository name: `vulnscan`
   - Description: `리눅스 시스템 CVE 취약점 원격 스캔 도구`
   - Public/Private 선택
   - **DO NOT** initialize with README (이미 있음)
4. `Create repository` 클릭

## 3단계: 원격 저장소 연결

GitHub에서 생성 후 나오는 명령어 중 선택:

### 방법 A: HTTPS (간단, 비밀번호 필요)

```bash
# 원격 저장소 추가 (username을 본인 GitHub ID로 변경)
git remote add origin https://github.com/username/vulnscan.git

# 브랜치 이름 확인/변경
git branch -M main

# 푸시
git push -u origin main
```

### 방법 B: SSH (권장, 설정 필요)

#### SSH 키 생성 (최초 1회)

```bash
# SSH 키 생성
ssh-keygen -t ed25519 -C "your_email@example.com"
# Enter 3번 (기본 경로, 비밀번호 없음)

# 공개키 출력
cat ~/.ssh/id_ed25519.pub
```

#### GitHub에 SSH 키 등록

1. 출력된 공개키 전체 복사 (`ssh-ed25519 AAAA...`)
2. GitHub → Settings → SSH and GPG keys
3. `New SSH key` 클릭
4. Title: `vulnscan-dev`
5. Key: 복사한 공개키 붙여넣기
6. `Add SSH key` 클릭

#### SSH로 푸시

```bash
# 원격 저장소 추가 (username을 본인 GitHub ID로 변경)
git remote add origin git@github.com:username/vulnscan.git

# 브랜치 이름 확인/변경
git branch -M main

# 푸시
git push -u origin main
```

## 4단계: 푸시 확인

```bash
# 원격 저장소 확인
git remote -v

# 브랜치 상태 확인
git branch -a

# 커밋 이력 확인
git log --oneline
```

GitHub 웹에서 저장소 확인: `https://github.com/username/vulnscan`

## 5단계: 이후 변경사항 푸시

```bash
# 파일 수정 후...

# 변경사항 확인
git status

# 스테이징
git add .

# 커밋
git commit -m "설명"

# 푸시
git push
```

## 주의사항

### .env 파일 보호

`.env` 파일은 `.gitignore`에 포함되어 있어 자동으로 제외됩니다.
**절대로 .env 파일을 Git에 포함하지 마세요!**

확인 방법:
```bash
git status
# .env 파일이 보이면 안 됨
```

### 대용량 파일

`nvd_cache.db` (1.1GB)가 포함되어 있습니다.

GitHub는 100MB 이상 파일에 경고가 나고, 2GB 이상은 거부합니다.

#### 해결 방법 1: Git LFS 사용 (권장)

```bash
# Git LFS 설치
sudo apt install git-lfs  # Ubuntu/Debian
# 또는
brew install git-lfs  # macOS

# LFS 초기화
git lfs install

# 큰 파일 추적
git lfs track "*.db"
git lfs track "*.json"

# .gitattributes 커밋
git add .gitattributes
git commit -m "Add Git LFS tracking"

# 기존 파일 다시 추가
git add nvd_cache.db debian_security_cache.json
git commit -m "Add cache files via Git LFS"

# 푸시
git push
```

#### 해결 방법 2: 제외하기

```bash
# .gitignore에 추가
echo "nvd_cache.db" >> .gitignore
echo "*_security_cache.json" >> .gitignore
echo "exploit_cache.json" >> .gitignore
echo "kev_cache.json" >> .gitignore

# README에 다운로드 방법 안내 추가
```

## 트러블슈팅

### "failed to push some refs"

```bash
# 원격 저장소 내용 먼저 가져오기
git pull origin main --rebase

# 다시 푸시
git push origin main
```

### "Permission denied (publickey)"

SSH 키가 등록되지 않았습니다. 위의 "SSH 키 생성" 단계 참고

### "remote: error: File is too large"

Git LFS 사용 또는 해당 파일 제외 (위 참고)

## 유용한 Git 명령어

```bash
# 상태 확인
git status

# 변경사항 확인
git diff

# 커밋 이력
git log --oneline --graph --all

# 특정 파일 제외
git rm --cached <file>

# 마지막 커밋 수정
git commit --amend

# 브랜치 생성
git checkout -b feature-name

# 원격 동기화
git fetch origin
git pull origin main
```
