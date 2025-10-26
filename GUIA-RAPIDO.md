# 🚀 GUIA RÁPIDO - 5 MINUTOS

## ⚠️ PROBLEMA IDENTIFICADO

**O servidor não arrancava porque:**
1. ❌ Faltava `require('dotenv').config()` no início do server.js
2. ❌ Variável `ALLOWED_ORIGINS` estava cortada no EasyPanel
3. ❌ Sem logs de debug para identificar problemas

## ✅ SOLUÇÃO APLICADA

Corrigi tudo no código! Agora só precisas de:

### PASSO 1: Upload para GitHub (2 min)

```bash
# Descarrega o ZIP "freguesia-backend-corrigido.zip"
# Extrai os ficheiros
# Copia para o teu repositório local
# Depois:

cd freguesia-portal-backend
git add .
git commit -m "Fix: Adicionar dotenv e corrigir CORS"
git push origin main
```

### PASSO 2: EasyPanel - Environment (1 min)

**CRÍTICO:** Vai a Environment e copia ESTA LINHA COMPLETA:

```
ALLOWED_ORIGINS=https://portal-freguesias-freguesia-backoffice.3isjct.easypanel.host,https://portal-freguesias-freguesia-frontend.3isjct.easypanel.host
```

**⚠️ TEM QUE TERMINAR EM `...easypanel.host` - NÃO PODE ESTAR CORTADA!**

### PASSO 3: Deploy (2 min)

1. ✅ Clica "Save"
2. ✅ Clica "Deploy"
3. ✅ Aguarda 2 minutos
4. ✅ Vai a "Logs"

### PASSO 4: Verificar Logs

**Deves ver isto:**

```
🔍 VERIFICAÇÃO DE VARIÁVEIS DE AMBIENTE
NODE_ENV: production
PORT: 5000
MONGODB_URI: ✅ Definido
JWT_SECRET: ✅ Definido
ALLOWED_ORIGINS: https://portal-freguesias-freguesia-backoffice...

🔐 CORS - Origens permitidas: [...]
🚀 Servidor iniciado: http://localhost:5000
✅ MongoDB conectado com sucesso
```

**Se vires isto = FUNCIONA! ✅**

### PASSO 5: Testar Login

Vai ao backoffice e tenta login:
- Email: `admin@freguesia.pt`
- Password: `Admin123!@#`

**Deve entrar SEM erros de CORS!** 🎉

---

## 🐛 SE AINDA NÃO FUNCIONAR

**Envia-me screenshots de:**
1. Tab "Logs" do freguesia-api (depois do deploy)
2. Tab "Environment" (variáveis completas)
3. Console do browser (F12) ao tentar login

---

## 📦 FICHEIROS INCLUÍDOS

- ✅ `server.js` - Corrigido com dotenv e logs
- ✅ `package.json` - Dependências corretas
- ✅ `.env.example` - Template das variáveis
- ✅ `.gitignore` - Não commitar ficheiros sensíveis
- ✅ `README-DEPLOY.md` - Guia completo detalhado
- ✅ `GUIA-RAPIDO.md` - Este ficheiro!

---

**TEMPO TOTAL: ~5 MINUTOS**

1. Git push (2 min)
2. Environment check (1 min)
3. Deploy + aguardar (2 min)
4. ✅ FUNCIONA!

**BOA SORTE! 🚀**
