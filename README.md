# 🛡️ Arquitetura de Autenticação Segura

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![Firebase](https://img.shields.io/badge/firebase-a08021?style=for-the-badge&logo=firebase&logoColor=ffcd34)
![Vercel](https://img.shields.io/badge/vercel-%23000000.svg?style=for-the-badge&logo=vercel&logoColor=white)

Este repositório contém o código-fonte do meu **Projeto de Final de Curso (PFC)**. O objetivo deste projeto foi desenvolver do zero um ecossistema de autenticação web focado em **Defesa em Profundidade**, mitigando as principais vulnerabilidades modernas, como força bruta, vazamento de dados e roubo de credenciais.

## ✨ Principais Funcionalidades de Segurança

- **Senhas Fortes (Regex):** Validação estrita no backend exigindo maiúsculas, minúsculas, números, símbolos e mínimo de 8 caracteres.
- **Hashing Criptográfico:** Senhas protegidas utilizando o algoritmo **Bcrypt** com *salt* exclusivo para cada usuário.
- **Autenticação em Dois Fatores (2FA):** Verificação de identidade via código OTP de 6 dígitos enviado por e-mail (válido por 10 minutos).
- **Proteção contra Força Bruta (Rate Limiting):** Bloqueio temporário da conta após 3 tentativas falhas de login.
- **Recuperação Duplamente Segura:** Redefinição de senha exige a validação de um Token criptográfico temporário na URL em conjunto com um código OTP recebido por e-mail.
- **Banco de Dados NoSQL:** Arquitetura na nuvem utilizando **Firebase Firestore**.

## 💻 Telas do Sistema

> **Nota:** Adicione prints do seu sistema aqui!
> 
> *Coloque as imagens na pasta do projeto e substitua os links abaixo:*
> - `![Tela de Login](caminho/para/login.png)`
> - `![Tela de 2FA](caminho/para/2fa.png)`
> - `![Dashboard](caminho/para/dashboard.png)`
