# JeaxLabs OS Updates

Repositório oficial do manifesto de atualizações e da ferramenta Python que empacota pacotes `.jxu`.

## Política de versões

Toda versão numerada publicada é tratada como versão oficial do JeaxLabs OS. Não publicar produto como beta, preview ou release candidate. O repositório principal `jeaxlabs-appstore` assina e publica cada versão oficial; esta workflow recebe o evento autenticado de publicação e atualiza `updates.json` automaticamente.

## Arquivos

- `updates.json`: manifesto público da versão mais recente publicada.
- `tools/JeaxLabsUpdatePacker.py`: empacotador de atualizações `.jxu`.
- `.github/workflows/sync-official-release.yml`: valida e grava metadados recebidos do repositório principal.
- `packages/`: espaço reservado para pacotes `.jxu`.

O manifesto atualizado inclui versão, versionCode Android, URL de download do pacote criptografado `.jxu`, SHA-256, tamanho, data de publicação e notas. O workflow rejeita versões fora do formato SemVer, checksums inválidos e tentativas de substituir uma versão mais recente por uma mais antiga.

## Integração e segurança

No repositório principal, configurar o secret `UPDATES_REPO_TOKEN` com permissão de escrita suficiente para disparar `repository_dispatch` neste repositório. O token não deve ser armazenado no código nem no manifesto.

Não armazenar chaves privadas, senhas ou tokens neste repositório. O empacotador GUI e o CLI `tools/JeaxLabsJxuCli.py` geram o mesmo formato `.jxu`, que contém a nova APK do JeaxLabs OS cifrada com AES-256-GCM e assinada com Ed25519.

O aplicativo verifica a impressão digital confiável, a assinatura, o hash, a senha, o pacote Android de destino, a versão e o versionCode antes de solicitar a instalação. A atualização substitui a instalação existente apenas quando o novo APK foi assinado pelo mesmo certificado Android e tem versionCode maior. A confirmação final depende das permissões de gerenciamento permitidas pelo próprio Android.

## Limites atuais

O manifesto é sincronizado automaticamente após a publicação oficial; a aplicação de `.jxu` foi integrada no código Android, mas ainda precisa passar pelo CI e por teste no tablet físico. Publicar uma versão oficial do APK não transforma o aplicativo em uma ROM/firmware independente.
