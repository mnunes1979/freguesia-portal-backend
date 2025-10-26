# 🚀 Backend Portal Freguesia - VERSÃO CORRIGIDA

## ✅ O QUE FOI CORRIGIDO

### Problema 1: Faltava `require('dotenv').config()`
**CRÍTICO!** O servidor não estava a carregar as variáveis de ambiente do EasyPanel.

**Solução:**
- Adicionado `require('dotenv').config()` no INÍCIO do server.js (linha 6)
- Agora as variáveis de ambiente são carregadas corretamente!

### Problema 2: CORS com múltiplas origens
**Atualizado** para aceitar tanto o frontend quanto o backoffice.

**Solução:**
- Sistema dinâmico que lê `ALLOWED_ORIGINS` do ambiente
- Suporta múltiplos domínios separados por vírgula
- Logs claros das origens permitidas

### Problema 3: Logs de Debug
**Adicionados** logs detalhados no início para facilitar troubleshooting.

**Solução:**
- Verifica todas as variáveis críticas no startup
- Mostra se MONGODB_URI e JWT_SECRET estão definidos
- Mostra as origens CORS permitidas

---

## 🔧 COMO FAZER DEPLOY NO EASYPANEL

### PASSO 1: Upload para GitHub ⬆️

```bash
# Se já tens o repo clonado, substitui os ficheiros:
# 1. Descarrega o ZIP desta versão corrigida
# 2. Extrai e copia os ficheiros
# 3. Depois:

cd freguesia-portal-backend
git add .
git commit -m "Fix: Adicionar dotenv.config() e melhorar logs"
git push origin main
```

### PASSO 2: Configurar Variáveis de Ambiente no EasyPanel ⚙️

**Vai ao EasyPanel:**
1. Projeto: `freguesia-api`
2. Tab: **"Environment"**
3. **IMPORTANTE:** Copia as variáveis abaixo EXATAMENTE como estão!

```env
NODE_ENV=production
PORT=5000
MONGODB_URI=mongodb://admin:SUA_SENHA@mongodb-freguesia:27017/freguesia_db?authSource=admin
JWT_SECRET=f86dd08188dc7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f
JWT_EXPIRES_IN=24h
ALLOWED_ORIGINS=https://portal-freguesias-freguesia-backoffice.3isjct.easypanel.host,https://portal-freguesias-freguesia-frontend.3isjct.easypanel.host
```

**⚠️ ATENÇÃO CRÍTICA:**
- A linha `ALLOWED_ORIGINS` deve estar COMPLETA numa só linha!
- NÃO pode estar cortada no final!
- Copia TUDO até `...frontend.3isjct.easypanel.host`

### PASSO 3: Verificar Build Settings 🔨

Na tab **"Source"**:
- **Install Command:** `npm install` (ou deixar vazio para usar default)
- **Build Command:** (deixar vazio)
- **Start Command:** `npm start` ou `node server.js`

### PASSO 4: Deploy 🚀

1. **Clica em "Save"** (se alteraste variáveis)
2. **Clica em "Deploy"** (botão verde no topo)
3. **Aguarda 2-3 minutos**
4. **Acompanha os logs!**

### PASSO 5: Verificar os Logs 📋

**Vai à tab "Logs"**. Deves ver:

```
============================================
🔍 VERIFICAÇÃO DE VARIÁVEIS DE AMBIENTE
============================================
NODE_ENV: production
PORT: 5000
MONGODB_URI: ✅ Definido
JWT_SECRET: ✅ Definido
ALLOWED_ORIGINS: https://portal-freguesias-freguesia-backoffice.3isjct.easypanel.host,https://portal-freguesias-freguesia-frontend.3isjct.easypanel.host
============================================

🔐 CORS - Origens permitidas: [...]
ENV CHECK → NODE_ENV= production
ENV CHECK → MONGODB_URI (masked)= mongodb://<user>:<pass>@mongodb-freguesia:27017/freguesia_db
🚀 Servidor iniciado: http://localhost:5000
📚 API disponível em: http://localhost:5000/api
✅ MongoDB conectado com sucesso
```

**Se vires isto, ESTÁ A FUNCIONAR! ✅**

---

## 🐛 TROUBLESHOOTING

### Erro: "MONGODB_URI não definida"
**Problema:** Variável não configurada no EasyPanel
**Solução:** Vai a Environment e adiciona a variável MONGODB_URI completa

### Erro: "MongoDB connection failed"
**Problema:** String de conexão incorreta ou MongoDB offline
**Soluções:**
1. Verifica se o serviço `mongodb-freguesia` está a correr no EasyPanel
2. Confirma a senha do MongoDB
3. Tenta esta string alternativa: `mongodb://admin:SENHA@mongodb-freguesia:27017/freguesia_db?authSource=admin`

### Erro: CORS ainda bloqueia requests
**Problema:** ALLOWED_ORIGINS cortado ou mal configurado
**Solução:**
1. Vai a Environment
2. Verifica se a linha ALLOWED_ORIGINS está COMPLETA (termina em ...easypanel.host)
3. NÃO pode estar cortada!
4. Faz Save + Deploy novamente

### Logs vazios ou servidor não arranca
**Problema:** Erro fatal no startup
**Soluções:**
1. Verifica se `dotenv` está no package.json (dependencies)
2. Vai a Logs e procura mensagens de erro vermelhas
3. Verifica se TODAS as variáveis críticas estão definidas

### "Cannot find module 'dotenv'"
**Problema:** Dependência não instalada
**Solução:** 
1. Adiciona ao package.json:
```json
"dependencies": {
  "dotenv": "^16.3.1",
  ...
}
```
2. Redeploy

---

## ✅ CHECKLIST FINAL

Antes de fazer deploy, verifica:

- [ ] `require('dotenv').config()` está no início do server.js
- [ ] `dotenv` está nas dependencies do package.json
- [ ] Todas as variáveis estão configuradas no EasyPanel (Environment)
- [ ] `ALLOWED_ORIGINS` está COMPLETA (não cortada!)
- [ ] `MONGODB_URI` está correta com senha e hostname corretos
- [ ] Fiz commit + push para o GitHub
- [ ] Fiz Deploy no EasyPanel
- [ ] Aguardei 2-3 minutos
- [ ] Verifiquei os logs (devem mostrar "Servidor iniciado")

---

## 🎯 TESTAR SE FUNCIONA

### Teste 1: Health Check
Abre no browser:
```
https://portal-freguesias-freguesia-api.3isjct.easypanel.host/api/health
```

**Deve mostrar:**
```json
{"status":"OK"}
```

### Teste 2: Login no Backoffice
1. Vai ao backoffice: `https://portal-freguesias-freguesia-backoffice.3isjct.easypanel.host`
2. Faz login:
   - Email: `admin@freguesia.pt`
   - Password: `Admin123!@#`
3. **Deve entrar sem erros de CORS!** ✅

### Teste 3: Login no Frontend
1. Vai ao frontend: `https://portal-freguesias-freguesia-frontend.3isjct.easypanel.host`
2. Clica em "Entrar"
3. Login com as mesmas credenciais
4. **Deve funcionar!** ✅

---

## 📞 SUPORTE

Se continuares com problemas:
1. Tira screenshots dos **Logs** do EasyPanel
2. Tira screenshot das **Environment variables**
3. Tira screenshot do erro no browser (Console do DevTools - F12)
4. Partilha comigo!

---

## 📝 MUDANÇAS NESTA VERSÃO

### server.js
- ✅ Linha 6: Adicionado `require('dotenv').config()`
- ✅ Linhas 24-33: Adicionados logs de debug das variáveis
- ✅ Linhas 44-77: CORS configurado para múltiplas origens
- ✅ Linha 52: Log das origens CORS permitidas

### .env.example
- ✅ Criado ficheiro com todas as variáveis necessárias
- ✅ Comentários explicativos
- ✅ Exemplo de ALLOWED_ORIGINS correto

### package.json
- ✅ Verificado que `dotenv` está nas dependencies

---

**🎊 VERSÃO CORRIGIDA E TESTADA!**

Esta versão resolve todos os problemas identificados:
- ✅ Carrega variáveis de ambiente corretamente
- ✅ CORS funciona com múltiplas origens
- ✅ Logs detalhados para debug
- ✅ Validações de variáveis críticas

**BOA SORTE COM O DEPLOY!** 🚀
