# Project Goal

Turn this tool into a high-signal semi-autonomous web bug bounty assistant.

## Primary focus
- IDOR
- Broken Access Control
- Authentication / Authorization flaws
- Business Logic
- API Security

## Avoid
- low-value open redirect / CORS / SSRF wandering
- random broad recon
- treating endpoint discovery as a finding
- revisiting dead branches
- low-confidence reporting
- wasting time on public/static/cart/checkout surfaces unless they clearly lead to real impact

## Desired improvements
1. SKILL.md optimization
2. dead-branch memory
3. endpoint scoring
4. multi-account session handling
5. exploit-path reasoning
6. stronger report threshold

## Working style
- incremental changes only
- small reviewable patches
- inspect before editing
- do not rewrite the whole repo blindly
- keep changes testable
