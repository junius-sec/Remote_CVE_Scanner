# GitHub 업로드 가이드

## 준비 완료!

모든 파일(대용량 포함)이 Git LFS로 설정되어 커밋되었습니다.

### 현재 상태
- Git LFS 설치 및 설정 완료
- nvd_cache.db (1.1GB) - Git LFS로 추적
- debian_security_cache.json (67MB) - Git LFS로 추적
- ubuntu_security_cache.json (37MB) - Git LFS로 추적
- 총 3개 커밋 준비 완료

---

## GitHub에 푸시하기

### 1단계: GitHub 저장소 생성

1. https://github.com 접속 및 로그인
2. 우측 상단 `+` 버튼 → `New repository` 클릭
3. 저장소 정보 입력:
   - Repository name: `vulnscan`
   - Description: `리눅스 시스템 CVE 취약점 원격 스캔 도구`
   - Public/Private 선택
   - **DO NOT** initialize with README (이미 있음)
4. `Create repository` 클릭

### 2단계: 원격 저장소 연결 및 푸시

#### 방법 A: HTTPS (간단)

```bash
# 원격 저장소 추가 (username을 본인 GitHub ID로 변경)
git remote add origin https://github.com/username/vulnscan.git

# 브랜치 이름 확인
git branch -M main

# PATH에 Git LFS 추가 후 푸시
export PATH="$HOME/.local/bin:$PATH"
git push -u origin main
```

**중요**: Git LFS 파일을 푸시하려면 반드시 `export PATH="$HOME/.local/bin:$PATH"` 먼저 실행하세요!

#### 방법 B: SSH (권장)

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

# 브랜치 이름 확인
git branch -M main

# PATH에 Git LFS 추가 후 푸시
export PATH="$HOME/.local/bin:$PATH"
git push -u origin main
```

### 3단계: 푸시 완료 확인

```bash
# 원격 저장소 확인
git remote -v

# 브랜치 상태 확인
git branch -a

# 커밋 이력 확인
git log --oneline
```

GitHub 웹에서 저장소 확인: `https://github.com/username/vulnscan`

**Git LFS 파일 확인**: 대용량 파일(nvd_cache.db 등)이 "Stored with Git LFS" 표시되어야 정상입니다.

### 4단계: 이후 변경사항 푸시

```bash
# 파일 수정 후...

# PATH 설정 (매번 필요)
export PATH="$HOME/.local/bin:$PATH"

# 변경사항 확인
git status

# 스테이징
git add .

# 커밋
git commit -m "설명"

# 푸시
git push
```

---

## Git LFS 주의사항

### .env 파일 보호

`.env` 파일은 `.gitignore`에 포함되어 있어 자동으로 제외됩니다.
**절대로 .env 파일을 Git에 포함하지 마세요!**

확인 방법:
```bash
git status
# .env 파일이 보이면 안 됨
```

## Git LFS 주의사항

### PATH 설정 필수

매번 Git 명령 실행 시 다음 명령을 먼저 실행해야 합니다:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

영구 설정하려면:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### GitHub LFS 용량 제한

- **무료 계정**: 무제한 저장소, 1GB/월 대역폭
- **Pro 계정**: 무제한 저장소, 50GB/월 대역폭

현재 nvd_cache.db가 1.1GB이므로:
- 저장소는 정상 (단일 파일 2GB 제한)
- clone/pull 시 대역폭 소비 (처음 clone 시 1.1GB)

---

## .env 파일 보호

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
