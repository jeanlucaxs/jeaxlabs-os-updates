# JeaxLabs OS Updates

Repositório público com o manifesto de atualizações do JeaxLabs OS e a pasta pública destinada a pacotes JXA da Store.

## Arquivos

- `updates.json`: manifesto da versão oficial mais recente do JeaxLabs OS.
- `.github/workflows/sync-official-release.yml`: valida e grava metadados recebidos do repositório principal.
- `packages/`: espaço reservado para arquivos de app publicados em versões antigas; a Store atual usa `packages/` no repositório `jeaxlabs-appstore`.

## Segurança e publicação

O repositório principal `jeaxlabs-appstore` gera o pacote de atualização `.jxu` no runner de release e sincroniza aqui os metadados. Não há utilitários Python de empacotamento distribuídos na árvore pública.

Não armazene chaves privadas, senhas ou tokens neste repositório. A Store de aplicativos usa o repositório público `jeaxlabs-appstore/packages/` porque o tablet consulta o catálogo sem token incorporado no APK.

O aplicativo verifica assinatura, integridade e versão antes de encaminhar uma atualização ao instalador Android. O sistema pode exigir confirmação, e a substituição depende do certificado Android da instalação existente e de um versionCode maior.

## Limites

O JeaxLabs OS é um launcher/kiosk sobre Android, não uma ROM/firmware independente. A compilação e a instalação em tablet físico precisam ser validadas separadamente.
