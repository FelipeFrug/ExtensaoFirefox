# Metodologia do Privacy Score

O **Privacy Guardian** atribui a cada página visitada uma pontuação de **0 a 100**.
A nota começa em 100 e é **decrementada** com base em sinais detectados durante a
navegação. Cada categoria possui um **teto de penalidade** ("cap") para evitar que
um único tipo de sinal — por exemplo, dezenas de imagens carregadas de um mesmo CDN
— derrube o score sozinho, distorcendo o resultado.

## Justificativa

A literatura sobre rastreamento web (Englehardt & Narayanan, 2016; Mozilla
Privacy Not Included; EFF Privacy Badger) identifica vetores recorrentes:
conexões a terceiros, cookies persistentes, supercookies, fingerprinting e
sincronismo de identificadores entre domínios. Cada vetor representa um custo
diferente para a privacidade — por isso, ponderamos cada sinal pelo seu
**potencial de identificação persistente** e pelo **grau de consentimento
ausente** (quanto menos consciente do uso o usuário está, maior a penalidade).

| Sinal | Por evento | Cap | Justificativa |
|---|---|---|---|
| Domínio de terceira parte | −2 | −20 | Cada terceiro recebe metadados (IP, User-Agent, Referer) — base de tracking passivo. |
| Tracker conhecido | −3 | −25 | Domínios catalogados (Google Ads, Facebook, etc.) cuja função primária é rastrear. |
| Domínio suspeito | −8 | −16 | Padrões associados a cryptojacking, malvertising ou push abuse. |
| Cookie de 3ª parte | −3 | −20 | Mecanismo clássico de identificação cross-site. |
| Cookie persistente de 1ª parte | −1 | −5 | Pode ser legítimo (sessão prolongada), mas pesa quando há muitos. |
| Supercookie (ETag/HSTS) em 3P | −3 cada | −15 | Identificadores que sobrevivem à limpeza de cookies. |
| API de fingerprinting | −5 cada | −20 | Canvas/WebGL/AudioContext acessadas — sinal forte de fingerprinting. |
| Hijacking / hooking | −8 cada | −20 | Redirects suspeitos, scripts injetados, popup spam. |
| Cookie syncing | −6 cada | −18 | Mesmo identificador propagado entre domínios distintos. |
| Web Storage em terceiros | −1 a cada 5 chaves | −8 | Persistência local de dados em domínios externos. |

`score = max(0, 100 − Σ penalidades)`

## Classificação

| Faixa | Rótulo | Cor |
|---|---|---|
| 85 – 100 | **Excelente** | verde-escuro |
| 70 – 84 | **Bom** | verde |
| 50 – 69 | **Razoável** | âmbar |
| 30 – 49 | **Ruim** | laranja |
| 0 – 29 | **Crítico** | vermelho |

## Decisões de projeto

- **Por aba, não global.** O score reflete apenas a sessão ativa — assim ele
  responde imediatamente quando o usuário muda de página, e permite comparar
  sites lado a lado.
- **Sem bloqueio.** Esta extensão é puramente **observacional**: não tenta
  impedir requisições nem reescrever cookies. O objetivo é didático —
  expor o que está acontecendo — não substituir uBlock Origin / Privacy Badger.
- **Heurísticas, não verdade absoluta.** A lista de trackers conhecidos é
  curta (≈ 60 domínios) e a detecção de fingerprinting reporta acessos a APIs
  que também podem ter usos legítimos (jogos, editores de imagem). O score
  deve ser lido como um **indicador qualitativo**, não como um veredicto.
- **Caps por categoria.** Sem teto, sites pesados em mídia (CDNs múltiplos)
  receberiam notas piores que sites de tracking puro com poucas dependências.
  Os caps mantêm o equilíbrio entre os vetores.

## Limitações conhecidas

1. **CSP estrito** pode impedir a injeção do `inject.js`, reduzindo a
   detecção de fingerprinting para sinais observáveis externamente apenas.
2. A heurística de cookie syncing usa padrões de "tracking-like ID"
   (UUID, hex longo, base64 alta entropia); pode gerar falsos positivos em
   sites que passam tokens legítimos em parâmetros de URL.
3. Supercookies em ETag são apenas **registrados** — não validamos se o
   navegador realmente reusou o valor numa requisição posterior.
4. A lista de TLDs de duas partes é simplificada e pode falhar em alguns
   sufixos exóticos. Para uso em produção, integrar a Public Suffix List
   completa.
