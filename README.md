# Privacy Guardian

Extensão WebExtension para **Firefox** que detecta e apresenta os principais
vetores de rastreamento e violação de privacidade durante a navegação web.

> Projeto desenvolvido para a disciplina **TecHack — Roteiro 4** (Insper, 2026.1).

---

## O que a extensão detecta

| # | Vetor | Onde aparece no popup |
|---|---|---|
| 1 | **Conexões a domínios de terceira parte** com classificação por tipo de recurso (script, image, iframe, xhr, font, media, websocket…) | Aba *Terceiros* |
| 2 | **Hijacking / hooking** — scripts externos suspeitos e redirects não autorizados | Aba *Ameaças* |
| 3 | **Web Storage** (`localStorage`, `sessionStorage`) e **IndexedDB** — chaves, tamanhos e domínios responsáveis | Aba *Storage* |
| 4 | **Cookies** classificados por: 1ª × 3ª parte, sessão × persistente, e **supercookies** (HSTS, ETag) | Aba *Cookies* |
| 5 | **Browser fingerprinting** — chamadas a `Canvas.toDataURL`/`getImageData`, `WebGL.getParameter`/`WEBGL_debug_renderer_info`, `AudioContext.createOscillator`/`createDynamicsCompressor` | Aba *Fingerprint* |
| 6 | **Cookie syncing** — identificadores propagados entre domínios | Aba *Ameaças* |
| 7 | **Privacy Score (0–100)** com penalidades por categoria | Cartão superior |

A metodologia do score está documentada e justificada em
[`docs/PRIVACY_SCORE.md`](docs/PRIVACY_SCORE.md).

---

## Instalação

1. Abra o Firefox e acesse `about:debugging`.
2. Clique em **"Este Firefox"** no menu lateral.
3. Clique em **"Carregar extensão temporária…"**.
4. Selecione o arquivo `manifest.json` deste diretório.
5. A extensão aparecerá com o ícone na barra de ferramentas.

> Extensões temporárias são removidas quando o Firefox é fechado — basta
> recarregar pelos passos acima.

---

## Uso

1. Visite qualquer site.
2. Clique no ícone do **Privacy Guardian** na barra de ferramentas.
3. Navegue pelas abas no popup:
   - **Terceiros** — domínios externos contactados e tipo de recurso.
   - **Cookies** — distribuição 1ª/3ª parte, sessão/persistente, supercookies.
   - **Storage** — `localStorage`, `sessionStorage` e IndexedDB por origem.
   - **Fingerprint** — APIs de fingerprinting acionadas.
   - **Ameaças** — sinais de hijacking, hooking e cookie syncing.
4. O **Privacy Score** no topo é recalculado em tempo real.
5. O botão **↻** força um re-scan da aba atual.
