#!/usr/bin/env bash
# 오프라인 배포용 Docker 이미지를 빌드하고 tar.gz 로 패키징한다.
#
# 산출물 이름 규칙 (고정):
#   - 도커 이미지 : <서비스명>:<버전>        예) clustara:v0.9.205
#   - 배포 압축본 : <서비스명>-<버전>.tar.gz  예) clustara-v0.9.205.tar.gz
#
# 사용법:
#   ./scripts/release.sh VERSION [-i IMAGE] [-p PLATFORM]
#   ./scripts/release.sh [-v VERSION] [-i IMAGE] [-p PLATFORM]
#
# 예:
#   ./scripts/release.sh v0.1.0
#   ./scripts/release.sh v0.1.0 -p linux/arm64
#   ./scripts/release.sh -n v0.1.0        # 빌드 없이 산출물 이름만 출력
set -euo pipefail

IMAGE="clustara"
PLATFORM="linux/amd64"
VERSION=""
DRY_RUN=0

while getopts ":v:i:p:nh" opt; do
    case "$opt" in
        v) VERSION="$OPTARG" ;;
        i) IMAGE="$OPTARG" ;;
        p) PLATFORM="$OPTARG" ;;
        n) DRY_RUN=1 ;;
        h)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        :) echo "옵션 -$OPTARG 에 값이 필요합니다." >&2; exit 2 ;;
        \?) echo "알 수 없는 옵션: -$OPTARG" >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

# 위치 인자로도 버전을 받는다. 예전에는 getopts 만 봤기 때문에
# `release.sh v0.9.204` 처럼 부르면 인자가 조용히 무시되고 날짜-SHA 스탬프가
# 버전으로 쓰였다 (v0.9.181~v0.9.204 산출물 이름이 그렇게 어긋났다).
# 이제는 위치 인자를 받아들이고, 알 수 없는 인자는 조용히 넘기지 않고 실패한다.
if [[ $# -gt 0 ]]; then
    if [[ -n "$VERSION" && "$VERSION" != "$1" ]]; then
        echo "버전이 두 번 지정되었습니다: -v $VERSION / $1" >&2
        exit 2
    fi
    VERSION="$1"
    shift
fi
if [[ $# -gt 0 ]]; then
    echo "알 수 없는 인자: $*" >&2
    exit 2
fi

if [[ $DRY_RUN -eq 0 ]] && ! command -v docker >/dev/null 2>&1; then
    echo "docker 가 PATH 에 없습니다." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -z "$VERSION" ]]; then
    STAMP="$(date +%Y%m%d-%H%M)"
    if SHORT_SHA="$(git rev-parse --short HEAD 2>/dev/null)"; then
        VERSION="${STAMP}-${SHORT_SHA}"
    else
        VERSION="${STAMP}-nogit"
    fi
fi

TAG="${IMAGE}:${VERSION}"
SAFE_VERSION="$(echo "$VERSION" | sed 's/[^A-Za-z0-9._-]/_/g')"
RELEASE_DIR="${REPO_ROOT}/release"

TAR_PATH="${RELEASE_DIR}/${IMAGE}-${SAFE_VERSION}.tar"
GZ_PATH="${TAR_PATH}.gz"
SHA_PATH="${GZ_PATH}.sha256"
README_PATH="${RELEASE_DIR}/README-offline-${SAFE_VERSION}.md"

if [[ $DRY_RUN -eq 1 ]]; then
    # 이름 규칙만 검증하는 모드 (release_gate_test.go 가 이 출력을 고정한다).
    echo "image=${TAG}"
    echo "archive=${IMAGE}-${SAFE_VERSION}.tar.gz"
    exit 0
fi

mkdir -p "$RELEASE_DIR"

echo "[1/4] docker build $TAG (platform=$PLATFORM)"
docker build \
    --platform "$PLATFORM" \
    --build-arg "VERSION=${VERSION}" \
    -t "$TAG" \
    -f Dockerfile \
    .

echo "[2/4] docker save -> $TAR_PATH"
docker save -o "$TAR_PATH" "$TAG"

echo "[3/4] gzip 압축 -> $GZ_PATH"
gzip -9 -f "$TAR_PATH"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$RELEASE_DIR" && sha256sum "$(basename "$GZ_PATH")" > "$SHA_PATH")
elif command -v shasum >/dev/null 2>&1; then
    (cd "$RELEASE_DIR" && shasum -a 256 "$(basename "$GZ_PATH")" > "$SHA_PATH")
else
    echo "sha256sum / shasum 둘 다 없음 - 체크섬 생략" >&2
fi

SHA_VALUE=""
if [[ -f "$SHA_PATH" ]]; then
    SHA_VALUE="$(awk '{print $1}' "$SHA_PATH")"
fi

echo "[4/4] 오프라인 가이드 생성 -> $README_PATH"
GZ_NAME="$(basename "$GZ_PATH")"
SHA_NAME="$(basename "$SHA_PATH")"
cat > "$README_PATH" <<EOF
# Clustara - 오프라인 배포 패키지

- 버전: ${VERSION}
- 이미지: ${TAG}
- 플랫폼: ${PLATFORM}
- 파일: ${GZ_NAME}
- SHA256: ${SHA_VALUE}

## 폐쇄망 적재 절차

1. 무결성 확인

   \`\`\`bash
   sha256sum -c ${SHA_NAME}
   \`\`\`

2. 이미지 적재

   \`\`\`bash
   gunzip -c ${GZ_NAME} | docker load
   \`\`\`

3. 실행 (SQLite 파일을 호스트 볼륨에 보관)

   \`\`\`bash
   docker run -d --name clustara --restart=always \\
       -p 9090:9090 \\
       -v /opt/clustara/data:/data \\
       -e UPSTREAM_BASE_URL=https://api.openai.com \\
       -e UPSTREAM_API_KEY=sk-... \\
       -e ADMIN_TOKEN=change-me \\
       -e GATEWAY_SECRET=\$(openssl rand -hex 32) \\
       -e MODEL_PRICING_KRW_PER_1M='{"gpt-4.1-mini":{"input_krw_per_1m":540,"output_krw_per_1m":2160}}' \\
       ${TAG}
   \`\`\`

4. 관리자 UI

   - http://<host>:9090/admin
   - 토큰은 ADMIN_TOKEN 값
EOF

echo
echo "릴리즈 완료"
echo "  이미지   : $TAG"
echo "  파일     : $GZ_PATH"
echo "  SHA256   : ${SHA_PATH:-생략}"
echo "  가이드   : $README_PATH"
