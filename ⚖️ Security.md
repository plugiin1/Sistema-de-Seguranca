# ⚖️ Conformidade e Segurança (LGPD)
Este projeto foi desenvolvido com foco em robustez criptográfica e rastreabilidade, atendendo aos requisitos de proteção de dados pessoais.

## 1. Inventário e Registro de Operações (ROPA)
• Dados Coletados: E-mail e Senha.

• Finalidade: Autenticação segura e controle de acesso ao dashboard.

• Base Legal: Consentimento e Execução de Contrato (Acesso ao Serviço).

• Fluxo de Dados: Coleta via Flask > Hashing via bcrypt > Armazenamento no Firebase.

## 2. Política de Segurança da Informação (PSI)
A infraestrutura do sistema adota medidas técnicas rigorosas para impedir acessos não autorizados:

• Criptografia de Senhas: Uso do algoritmo bcrypt para garantir que senhas nunca sejam armazenadas em texto puro.

• Múltiplo Fator de Autenticação (2FA): Implementação obrigatória de código de verificação enviado via e-mail (SMTP Google).

• Gestão de Credenciais: Uso de variáveis de ambiente (.env) e proteção de chaves sensíveis (como firebase-key.json) através do .gitignore.

• Hospedagem Segura: Deploy realizado via Vercel com isolamento de segredos no painel administrativo do servidor.

## 3. Relatório de Impacto à Proteção de Dados (RIPD)
Identificamos e mitigamos riscos de privacidade através das seguintes ações:

• Risco: Acesso indevido por descoberta de senha.

• Mitigação: Exigência de 2FA físico via e-mail do usuário, impedindo o login apenas com a senha.

• Risco: Vazamento do banco de dados.

• Mitigação: Uso de hashes não reversíveis para senhas, tornando os dados inúteis para invasores.

## 4. Políticas e Termos (Resumo)
• Privacidade: Coletamos o mínimo necessário (e-mail) para a operação do sistema.

• Cookies: Utilizamos apenas cookies de sessão estritamente necessários para manter a integridade da navegação após o login.

• Termos de Uso: O usuário é responsável pela segurança da sua conta de e-mail utilizada para o 2FA.
 
