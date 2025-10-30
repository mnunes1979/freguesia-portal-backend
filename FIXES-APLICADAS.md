# Correções aplicadas — Backend (server.js)
Data: 2025-10-30T08:20:13.692265Z

## 1) Notícias (/api/news)
- **Removido `required` do campo `excerpt`** no `newsSchema` (o Backoffice não envia este campo).
- **Adicionado campo `category`** com enum: `geral|cultura|desporto|avisos|outros` (default `geral`).
- **POST /api/news** agora aceita `category` e trata `excerpt` vazio.
- **PUT /api/news/:id** agora também atualiza `category`.

## 2) Configurações do Site (/api/config)
- Criado **`SiteConfig` model** e **endpoints**:
  - `GET /api/config` — devolve config (cria com defaults se não existir).
  - `PUT /api/config` — **apenas admin** pode guardar; responde com mensagem de sucesso.

Campos suportados:
```
siteName, siteDescription, contactEmail, contactPhone, address,
facebookUrl, instagramUrl, emailNotifications, publicIncidences, requireApproval
```

## 3) Observações
- CORS já se encontra permissivo no projeto actual.
- Endpoints existentes de incidências permanecem inalterados.
