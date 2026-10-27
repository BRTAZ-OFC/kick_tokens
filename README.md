# kick_tokens — Cloudflare Worker Kick para LiveNexus

Worker **TypeScript**, usando OAuth 2.1 + PKCE conforme o projeto [Only Dashboard](https://github.com/roboloop/only-dashboard) (MIT). Nenhum login por e-mail adicional no LiveNexus.

## Configuracao Cloudflare

Conecte BRTAZ-OFC/kick_tokens ao Cloudflare Workers, branch **main**.

| Campo | Valor |
|---|---|
| Build command | Deixar vazio |
| Deploy command | npx wrangler deploy |
| Root directory | / |

O arquivo **wrangler.jsonc** cria o Worker kick-tokens e solicita um Cloudflare KV chamado KICK_STORE. A versao atual do Wrangler pode provisionar automaticamente o KV durante o deploy pelo GitHub.

### Variables & Secrets (runtime)

| Nome | Tipo | Valor |
|---|---|---|
| KICK_CLIENT_ID | Secret | Client ID da sua aplicacao Kick |
| KICK_CLIENT_SECRET | Secret | Client Secret da mesma aplicacao |
| LIVENEXUS_API_KEY | Secret | Chave aleatoria com pelo menos 32 caracteres; identica no backend LiveNexus |
| WORKER_URL | Text | Origem HTTPS do Worker (ex.: https://kick-tokens.SEU-SUBDOMINIO.workers.dev) |
| LIVENEXUS_ORIGIN | Text | Origem HTTPS do LiveNexus, sem barra no final |

Crie as variaveis no painel Cloudflare, **nunca no GitHub**. Se o deploy nao criar KICK_STORE, vincule manualmente um KV com esse nome em Settings > Bindings.

### Callback na Kick

Na aplicacao criada em https://kick.com/settings/developer, cadastre EXATAMENTE a URL:

**https://kick-tokens.SEU-SUBDOMINIO.workers.dev/auth/kick/callback**

Substitua pela origem verdadeira do Worker. A mesma origem deve constar em WORKER_URL.

## Rotas

- GET /health — publico, retorna estado online e se o Worker esta configurado.
- POST /api/kick/authorize — recebe JSON com user_id; retorna authorization_url para o backend abrir no popup.
- GET /auth/kick/callback — callback OAuth da Kick; guarda tokens no KV e avisa ao popup do LiveNexus, sem revelar credenciais.
- GET /api/kick/status?user_id=ID — dados do proprio canal conectado.
- PATCH /api/kick/channel — recebe user_id, title e/ou category_id. Atualiza titulo e categoria na API oficial.
- POST /api/kick/disconnect — recebe user_id e exclui a autorizacao.

**ATENCAO:** Todas as rotas /api/kick/* exigem Authorization: Bearer (LIVENEXUS_API_KEY) e devem ser chamadas **exclusivamente do backend**, nunca do React ou navegador. O user_id deve vir da sessao autenticada do usuario.

Os tokens sao armazenados separadamente por usuario no KV e nunca sao devolvidos ao navegador. O Worker nao fornece CORS para chamadas administrativas.

## Integracao LiveNexus (ainda nao implementada)

O backend atual do LiveNexus ainda chama /api/auth/kick/url e /api/livetitle/update. Para utilizar este Worker sera necessario adaptar apenas os caminhos da Kick nesses arquivos, mantendo Twitch, YouTube e autenticacao do LiveNexus intactos.

Esta criacao nao modifica o repositorio LiveNexus nem o Worker Innertube.

## Desenvolvimento

- npm install
- npm run check
- npm run dev

Referencias: https://github.com/roboloop/only-dashboard/blob/main/src/worker/providers/kick.ts e https://developers.cloudflare.com/workers/wrangler/configuration/
