# JeaxLabs OS Updates

Repositório inicial para metadados de versões e pacotes de atualização do JeaxLabs OS.

## Objetivo
- Publicar o manifesto de atualização.
- Distribuir pacotes de atualização no formato `.jxu`.
- Permitir que o cliente consulte a versão publicada a cada 24 horas.
- Validar versão, integridade e assinatura antes de aceitar uma atualização.

## Arquivos
- `updates.json`: manifesto inicial, sem atualizações publicadas.
- `packages/`: diretório reservado para pacotes `.jxu`.

## Segurança
Não armazenar chaves privadas, senhas ou tokens no repositório. O cliente deverá validar uma assinatura confiável e a integridade do pacote antes de instalar. Uma extensão de arquivo ou um certificado incluído no mesmo pacote não garante autenticidade por si só.

## Estado
Infraestrutura inicial. O formato criptográfico, o manifesto final e o instalador de atualizações ainda precisam ser implementados e testados.
