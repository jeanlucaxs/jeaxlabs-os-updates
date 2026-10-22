# JeaxLabs OS Updates

Repositório oficial do manifesto de atualizações e da ferramenta Python que empacota pacotes `.jxu`.

## Política de versões

Toda versão numerada publicada é tratada como versão oficial do JeaxLabs OS. Não publicar produto como beta, preview ou release candidate. O repositório principal `jeaxlabs-appstore` assina e publica cada versão oficial; esta workflow recebe o evento autenticado de publicação e atualiza `updates.json` automaticamente.

## Arquivos

- `updates.json`: manifesto público da versão mais recente publicada.
- `tools/JeaxLabsUpdatePacker.py`: empacotador de atualizações `.jxu`.
- `.github/workflows/sync-official-release.yml`: valida e grava metadados recebidos do repositório principal.
- `packages/`: espaço reservado para pacotes `.jxu`.

O manifesto atualizado inclui versão, versionCode Android, URL de download da APK, SHA-256, tamanho, data de publicação e notas. O workflow rejeita versões fora do formato SemVer, checksums inválidos e tentativas de substituir uma versão mais recente por uma mais antiga.

## Integração e segurança

No repositório principal, configurar o secret `UPDATES_REPO_TOKEN` com permissão de escrita suficiente para disparar `repository_dispatch` neste repositório. O token não deve ser armazenado no código nem no manifesto.

Não armazenar chaves privadas, senhas ou tokens neste repositório. O empacotador `.jxu` usa AES-256-GCM e assinatura Ed25519, mas isso não significa que o aplicativo Android já implemente a validação, descriptografia ou instalação desses pacotes.

## Limites atuais

O manifesto é publicado automaticamente para consumo externo; o mecanismo de atualização dentro do JeaxLabs OS ainda precisa de integração e testes no aplicativo. Publicar uma versão oficial do APK não transforma o aplicativo em uma ROM/firmware independente.
