# CertGuard AI - Extensão Chrome

## Descrição

A extensão CertGuard AI é uma solução avançada de segurança para gerenciamento de certificados digitais em sites de tribunais brasileiros. Ela oferece proteção em tempo real, monitoramento comportamental e integração com o sistema CertGuard AI.

## Funcionalidades

### 🔐 Segurança Avançada
- **Blockchain**: Auditoria imutável de todas as operações
- **IA**: Monitoramento comportamental em tempo real
- **Zero Trust**: Verificação contínua de segurança
- **Container Seguro**: Proteção de certificados digitais

### 🛡️ Monitoramento em Tempo Real
- Detecção de atividades suspeitas
- Análise de padrões de uso
- Alertas de segurança automáticos
- Tracking de formulários e submissões

### 🏛️ Integração com Tribunais
- Suporte para todos os principais tribunais brasileiros
- Detecção automática de sites jurídicos
- Monitoramento específico para cada tribunal
- Integração com sistemas processuais

## Sites Suportados

- **Tribunais Superiores**: STF, STJ, TST
- **Tribunais Regionais Federais**: TRF1, TRF2, TRF3, TRF4, TRF5
- **Tribunais Estaduais**: TJSP, TJRJ, TJMG, TJRS, TJPR, TJBA, TJSC, TJDFT, TJGO, TJCE

## Instalação

1. **Download**: Baixe os arquivos da extensão
2. **Modo Desenvolvedor**: Ative o modo desenvolvedor no Chrome
3. **Carregar Extensão**: Clique em "Carregar extensão sem compactação"
4. **Selecionar Pasta**: Escolha a pasta da extensão
5. **Ativar**: A extensão será instalada e ativada automaticamente

## Como Usar

### Primeira Configuração
1. Clique no ícone da extensão na barra de ferramentas
2. Faça login no sistema CertGuard AI
3. Configure seus certificados digitais
4. Defina as permissões de acesso

### Uso Diário
1. **Acesso Automático**: A extensão detecta automaticamente sites de tribunais
2. **Indicador de Segurança**: Ícone azul indica proteção ativa
3. **Painel de Controle**: Clique no ícone para ver o status de segurança
4. **Acesso Seguro**: Use o botão "Iniciar Acesso Seguro" para proteção completa

### Funcionalidades do Painel
- **Status de Segurança**: Verificação em tempo real
- **Atividade Atual**: Monitoramento de ações do usuário
- **Análise de Risco**: Score de segurança dinâmico
- **Certificado Ativo**: Informações do certificado em uso

## Recursos Técnicos

### Arquitetura
- **Manifest V3**: Versão mais recente das extensões Chrome
- **Service Worker**: Background script para monitoramento contínuo
- **Content Scripts**: Injeção de código para monitoramento
- **Storage API**: Armazenamento seguro de dados

### Permissões
- `storage`: Armazenamento de configurações
- `activeTab`: Acesso à aba ativa
- `scripting`: Injeção de scripts de segurança
- `webNavigation`: Monitoramento de navegação
- `cookies`: Gerenciamento de sessões
- `identity`: Autenticação

### Segurança
- **Criptografia**: Dados criptografados localmente
- **Tokens JWT**: Autenticação segura
- **HTTPS**: Comunicação segura com o backend
- **Sandboxing**: Isolamento de processos

## Indicadores de Segurança

### Status dos Componentes
- **🔗 Blockchain**: Auditoria imutável ativa
- **🤖 IA**: Monitoramento comportamental
- **🔒 Zero Trust**: Verificação contínua
- **📦 Container**: Proteção de certificados

### Níveis de Risco
- **Verde**: Seguro (Score 0.0-0.3)
- **Amarelo**: Atenção (Score 0.3-0.6)
- **Laranja**: Alerta (Score 0.6-0.8)
- **Vermelho**: Crítico (Score 0.8-1.0)

## Monitoramento e Logs

### Atividades Rastreadas
- Carregamento de páginas
- Submissão de formulários
- Uso de certificados digitais
- Cliques em elementos sensíveis
- Atalhos de teclado
- Navegação entre páginas

### Análise Comportamental
- Padrões de clique
- Frequência de atividades
- Horários de uso
- Localização geográfica
- Dispositivos utilizados

### Alertas de Segurança
- Atividade fora do horário
- Múltiplas tentativas de acesso
- Comportamento anômalo
- Uso suspeito de certificados
- Tentativas de bypass

## Integração com Backend

### Endpoints Utilizados
- `/api/auth/login`: Autenticação
- `/api/container/access`: Acesso ao container
- `/api/audit/log`: Logs de auditoria
- `/api/security/alerts`: Alertas de segurança

### Sincronização
- Envio automático de logs
- Sincronização de configurações
- Backup de atividades
- Relatórios de segurança

## Troubleshooting

### Problemas Comuns
1. **Extensão não carrega**: Verifique as permissões do Chrome
2. **Login não funciona**: Verifique a conexão com o backend
3. **Sites não detectados**: Confirme se o site está na lista suportada
4. **Slow performance**: Desative outras extensões temporariamente

### Logs de Debug
- Abra o DevTools (F12)
- Vá para a aba Console
- Procure por mensagens com "🔐"
- Reporte problemas com os logs

## Atualizações

### Histórico de Versões
- **v1.0.0**: Lançamento inicial
  - Suporte a tribunais brasileiros
  - Monitoramento básico
  - Integração com CertGuard AI

### Próximas Funcionalidades
- Suporte a Firefox e Edge
- Assinatura digital integrada
- Relatórios avançados
- Integração com mais tribunais

## Suporte

Para suporte técnico ou dúvidas:
- **Sistema**: https://certguard.ai/support
- **Email**: suporte@certguard.ai
- **Documentação**: https://docs.certguard.ai

## Desenvolvido por

CertGuard AI - Próxima Geração em Segurança Digital
© 2025 - Todos os direitos reservados