# Clustara Admin UI 디자인 규칙

이 문서는 관리자 UI를 추가·수정할 때 화면마다 간격과 폼 구조가 달라지는 문제를 방지하기 위한 구현 규칙입니다. 신규 화면은 임의의 inline `gap`, `margin`, `grid-template-columns`보다 아래 공통 클래스를 먼저 사용합니다.

## 1. 폼 기본 원칙

1. 라벨, 컨트롤, 도움말은 하나의 `.ui-field` 안에 배치합니다.
2. 라벨 문자열과 `<input>`을 공백 없이 직접 붙이지 않습니다.
3. 관련 필드는 `.ui-form-section`으로 묶고 섹션 제목과 목적을 제공합니다.
4. 2열 폼은 `.ui-form-grid`를 사용합니다. 960px 이하에서는 자동으로 1열이 됩니다.
5. 필수·선택 여부는 placeholder가 아니라 `.ui-required`, `.ui-optional`로 표시합니다.
6. placeholder는 예시 값에만 사용하며 라벨을 대신하지 않습니다.
7. 검증 조건이나 값의 의미는 `.ui-help`에 작성합니다.
8. 제출 결과는 `aria-live="polite"`인 `.ui-form-status`에 표시합니다.
9. 버튼은 `.ui-form-actions`에 모으고 보조 동작을 먼저, 최종 제출을 마지막에 둡니다.
10. 위험한 작업과 Secret 처리 원칙은 입력 필드 사이가 아니라 `banner` 또는 `section-lead warn`으로 분리합니다.

## 2. 표준 구조

```html
<form class="card-body ui-form">
  <div class="ui-form-section">
    <div class="ui-form-section-head">
      <div>
        <h3>배포 대상</h3>
        <p>클러스터와 Namespace를 선택합니다.</p>
      </div>
    </div>

    <div class="ui-form-grid">
      <label class="ui-field">
        <span class="ui-field-label">
          클러스터 <span class="ui-required">필수</span>
        </span>
        <select required>...</select>
        <span class="ui-help">등록된 배포 대상 클러스터입니다.</span>
      </label>

      <label class="ui-field">
        <span class="ui-field-label">
          Namespace <span class="ui-optional">선택</span>
        </span>
        <input placeholder="예: production">
        <span class="ui-help">비우면 default를 사용합니다.</span>
      </label>
    </div>
  </div>

  <div class="ui-form-actions">
    <span class="ui-form-status" aria-live="polite"></span>
    <button type="button" class="secondary">미리보기</button>
    <button type="submit">저장</button>
  </div>
</form>
```

## 3. 간격과 크기 토큰

| 대상 | 규칙 |
| --- | --- |
| 폼 섹션 사이 | 20px |
| 필드 행·열 간격 | 16px / 18px |
| 라벨과 컨트롤 | 7px |
| 섹션 내부 여백 | 16px, 모바일 13px |
| input/select 최소 높이 | 40px |
| textarea 최소 높이 | 112px |
| 라벨 크기 | 11.5px, 굵기 850 |
| 도움말 크기 | 10px, line-height 1.45 |

간격을 바꿔야 한다면 화면별 inline style을 추가하기 전에 공통 토큰 변경이 타당한지 검토합니다.

## 4. 서비스 플랫폼 추가 규칙

- 서비스 생성은 `배포 대상 → 서비스 식별과 실행 환경 → Credential 참조 → 정책 미리보기 → 생성` 순서를 유지합니다.
- Secret 원문을 입력받지 않습니다. Kubernetes Secret 이름과 key 참조만 입력합니다.
- 운영 환경, digest 고정, 승인 필요 여부는 제출 버튼 주변이 아니라 해당 필드 도움말과 보안 banner에서 미리 안내합니다.
- 템플릿 버전 등록은 `버전 기본 정보`와 `렌더링 템플릿`을 분리합니다.
- 템플릿의 draft/active 상태와 사용자 노출 여부를 폼 상단에서 명시합니다.
- JSON/YAML 템플릿은 monospace textarea와 예시 placeholder를 사용합니다.

## 5. 금지 패턴

```html
<!-- 금지: 라벨과 입력이 붙고 필수 여부와 설명이 없음 -->
<label>버전<input placeholder="1.0"></label>

<!-- 금지: 화면마다 임의 간격을 정의 -->
<form style="display:grid;gap:8px">

<!-- 금지: placeholder가 라벨을 대체 -->
<input placeholder="클러스터 ID">

<!-- 금지: 제출과 보조 동작의 우선순위가 불명확 -->
<div><button>저장</button> <button>미리보기</button></div>
```

## 6. 리뷰 체크리스트

- [ ] 모든 입력에 시각적 라벨이 있는가?
- [ ] 라벨·입력·도움말 사이에 공통 간격이 적용됐는가?
- [ ] 필수와 선택 항목을 placeholder가 아닌 별도 텍스트로 표시했는가?
- [ ] 관련 필드가 의미 단위 섹션으로 묶였는가?
- [ ] 모바일 1열에서 순서가 자연스러운가?
- [ ] 오류가 발생한 필드와 해결 방법을 사용자가 알 수 있는가?
- [ ] 결과 영역에 `aria-live`가 적용됐는가?
- [ ] 보조 버튼이 먼저, 최종 제출 버튼이 마지막인가?
- [ ] Secret 원문이나 민감정보를 저장·재표시하지 않는가?
- [ ] 임의 inline 간격 대신 공통 클래스를 사용했는가?

