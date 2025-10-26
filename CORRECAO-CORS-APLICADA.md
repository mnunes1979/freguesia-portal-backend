# ✅ CORREÇÃO DE CORS APLICADA

## 🔧 O QUE FOI CORRIGIDO?

O backend estava configurado para aceitar requisições de apenas **UMA origem** (FRONTEND_URL), mas agora aceita **múltiplas origens**!

---

## 📝 ALTERAÇÕES FEITAS

### **1. server.js (linhas 43-50)**

**ANTES:**
```javascript
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  // ...
};
```

**DEPOIS:**
```javascript
// Lê múltiplas origens da variável ALLOWED_ORIGINS
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173'
    ];

const corsOptions = {
  origin: function (origin, callback) {
    // Valida se a origem está na lista permitida
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  // ...
};
```

### **2. .env.example**

Adicionada nova variável:
```env
ALLOWED_ORIGINS=https://portal-freguesias-freguesia-frontend.3isjct.easypanel.host,https://portal-freguesias-freguesia-backoffice.3isjct.easypanel.host
```

---

## 🚀 COMO FAZER O DEPLOY

### **PASSO 1: Fazer Commit e Push**

```bash
cd freguesia-portal-backend-main

# Adicionar todas as alterações
git add .

# Fazer commit
git commit -m "Fix: Corrigir CORS para múltiplas origens"

# Push para o GitHub
git push origin main
```

### **PASSO 2: Atualizar Variável no EasyPanel**

1. Abre o EasyPanel
2. Vai para o projeto `freguesia-api`
3. Clica em **"Environment"**
4. **ATUALIZA** a linha 7 (ALLOWED_ORIGINS):

**DE:**
```
ALLOWED_ORIGINS=https://portal-freguesias-freguesia-backoffice.3isjct.easypanel.host,https://portal-freguesias-freguesia-frontend.3isjct.easypanel.host
```

**PARA** (adiciona o domínio correto do frontend se for diferente):
```
ALLOWED_ORIGINS=https://portal-freguesias-freguesia-backoffice.3isjct.easypanel.host,https://COLOCA-AQUI-O-DOMINIO-DO-FRONTEND.3isjct.easypanel.host
```

5. Clica em **"Save"**
6. Clica em **"Deploy"** (botão verde)
7. Aguarda 2-3 minutos

### **PASSO 3: Testar**

1. Vai ao Backoffice
2. Faz **F5** (refresh)
3. Tenta fazer login:
   - Email: `admin@freguesia.pt`
   - Password: `Admin123!@#`

**Deve funcionar!** ✅

---

## 🔍 COMO VERIFICAR SE ESTÁ A FUNCIONAR

### **1. Logs do Backend**

Quando o backend iniciar, vais ver no log:
```
🔐 CORS - Origens permitidas: [
  'https://portal-freguesias-freguesia-backoffice.3isjct.easypanel.host',
  'https://portal-freguesias-freguesia-frontend.3isjct.easypanel.host'
]
```

### **2. Console do Browser**

1. Abre DevTools (F12)
2. Tab "Console"
3. Quando fizeres login, **NÃO** deve aparecer erros de CORS!

---

## 🎯 BENEFÍCIOS DA CORREÇÃO

✅ **Frontend** e **Backoffice** funcionam simultaneamente  
✅ Logs mostram qual origem está a fazer requests  
✅ Bloqueio de origens não autorizadas  
✅ Fácil adicionar novos domínios (só editar a variável)  
✅ Suporte para localhost (desenvolvimento)  

---

## 📋 ESTRUTURA FINAL

```
freguesia-portal-backend-main/
├── server.js          ← MODIFICADO (CORS corrigido)
├── .env.example       ← MODIFICADO (nova variável)
├── package.json
└── .gitignore
```

---

## 🐛 TROUBLESHOOTING

### Problema: Ainda dá erro de CORS

**Solução 1:** Confirma que a variável ALLOWED_ORIGINS no EasyPanel tem AMBOS os domínios:
```
ALLOWED_ORIGINS=https://backoffice.dominio,https://frontend.dominio
```

**Solução 2:** Confirma que fizeste redeploy depois de alterar a variável

**Solução 3:** Limpa a cache do browser (Ctrl+Shift+Del)

### Problema: Login dá "Network Error"

**Solução:** Verifica se o backend está online:
```
https://portal-freguesias-freguesia-api.3isjct.easypanel.host/api/health
```

Deve retornar: `{"status":"OK"}`

---

## ✅ CHECKLIST FINAL

Antes de considerar completo:

- [ ] Ficheiros corrigidos (server.js + .env.example)
- [ ] Commit feito no GitHub
- [ ] Push feito
- [ ] Variável ALLOWED_ORIGINS atualizada no EasyPanel
- [ ] Redeploy feito no EasyPanel
- [ ] Backend a correr (bolinha verde)
- [ ] Login funciona no Backoffice
- [ ] Login funciona no Frontend

---

**🎉 Depois de seguir todos os passos, o CORS vai estar RESOLVIDO!**
