# Projeto SSI — Chat Seguro com End-to-End Encryption

> **Unidade curricular:** Segurança de Sistemas Informáticos  
> **Tema:** Sistema de conversação seguro com E2EE  
> **Linguagem:** Python  
> **Biblioteca criptográfica:** `cryptography`  
> **Grupo:** Diogo Costa A107328 | Gonçalo Costa A107381 | Lourenço Martins A106849

---

## 1. Introdução

O objetivo do projeto foi implementar um sistema de conversação cliente-servidor em que o conteúdo das mensagens é protegido por cifragem ponta-a-ponta. O servidor é usado para coordenar ligações, autenticar utilizadores, encaminhar mensagens, gerir certificados, guardar mensagens offline e manter a informação necessária para grupos. No entanto, as mensagens são cifradas no cliente antes de chegarem ao servidor, pelo que o servidor não deve conseguir ler o seu conteúdo.

O modelo de segurança considerado assume um servidor **honesto mas curioso**: espera-se que o servidor siga o protocolo e execute a lógica funcional, mas não se confia nele para efeitos de confidencialidade dos dados. Também se assume que a rede pode ser controlada por um atacante ativo, capaz de observar tráfego, tentar alterar mensagens, fazer replay, ou tentar substituir a raiz de confiança do sistema.

A solução usa a biblioteca `cryptography` para as primitivas criptográficas principais: AES-GCM, RSA-PSS, RSA-OAEP, X25519, HKDF-SHA256 e certificados X.509.

---

## 2. Estrutura do projeto

A versão final foi organizada por responsabilidade, para facilitar a leitura, os testes e a defesa do protocolo.

```text
cliente.py
servidor.py
rede.py
cripto.py
pki.py
protocolo.py
validacao.py
persistencia.py
```

### 2.1 `cliente.py`

Implementa a interface textual do utilizador e a maior parte da lógica ponta-a-ponta. Trata de:

- carregar a CA confiável local;
- validar a CA do servidor por pinning/fingerprint;
- carregar ou gerar a identidade RSA do utilizador;
- enviar comandos como `/listar`, `/msg`, `/grupo criar`, `/grupo msg` e `/grupo membros`;
- iniciar e completar handshakes X25519;
- cifrar, assinar, decifrar e verificar mensagens privadas;
- instalar chaves de grupo;
- cifrar e verificar mensagens de grupo;
- gerir buffers defensivos para mensagens que cheguem antes da respetiva chave.

### 2.2 `servidor.py`

Implementa o servidor TCP. É responsável por:

- aceitar ligações;
- autenticar utilizadores;
- manter a base de dados de chaves públicas;
- emitir certificados X.509;
- encaminhar mensagens privadas e de grupo;
- guardar e entregar mensagens offline;
- guardar e entregar chaves de grupo cifradas;
- assinar mensagens de controlo enviadas aos clientes;
- proteger a chave privada da CA com password.

### 2.3 `rede.py`

Implementa o framing das mensagens sobre TCP:

```text
[4 bytes de tamanho][conteúdo]
```

Também define um limite máximo de 1 MiB por pacote, para evitar consumo excessivo de memória por mensagens demasiado grandes.

### 2.4 `cripto.py`

Contém primitivas criptográficas gerais:

- geração/carregamento de identidades RSA;
- RSA-OAEP para embrulhar chaves AES;
- RSA-PSS para assinaturas;
- AES-GCM para cifragem autenticada;
- X25519 para acordo de chaves;
- HKDF-SHA256 para derivação de chaves.

### 2.5 `pki.py`

Agrupa a lógica de PKI:

- geração da CA self-signed;
- emissão de certificados de utilizador;
- verificação de certificados;
- validação da CA local;
- cálculo de fingerprint SHA-256 da CA.

### 2.6 `protocolo.py`

Define payloads assinados e contextualizados do protocolo, como:

- mensagens de controlo do servidor;
- mensagens de grupo;
- `SESSION_INIT`;
- `SESSION_ACK`;
- contexto usado no HKDF.

### 2.7 `validacao.py`

Centraliza a validação de identificadores. Usernames e nomes de grupo seguem a regra:

```text
[A-Za-z0-9_-]{3,32}
```

Isto evita ambiguidades no protocolo textual, onde `:` é usado como separador.

### 2.8 `persistencia.py`

Contém funções auxiliares para carregar e guardar ficheiros JSON de runtime, usando permissões restritivas.

---

## 3. Funcionalidades implementadas

### 3.1 Identidade dos utilizadores

Cada utilizador possui:

- um username único;
- uma chave privada RSA protegida por password;
- uma chave pública RSA;
- um certificado X.509 emitido pela CA do sistema.

Os ficheiros locais têm o formato:

```text
<username>_privada.pem
<username>_publica.pem
<username>_cert.pem
```

A chave privada é guardada com `serialization.BestAvailableEncryption` e a password é introduzida com `getpass`, para não aparecer escrita no terminal.

### 3.2 Autenticação por challenge-response

Quando um cliente se liga ao servidor, envia o username e a chave pública. O servidor verifica se o username já existe:

- se for novo, guarda a chave pública;
- se já existir, exige que a chave pública seja a mesma já registada.

Depois o servidor envia um desafio aleatório de 32 bytes. O cliente assina esse desafio com a sua chave privada RSA e o servidor verifica a assinatura com a chave pública registada. Assim, o cliente prova posse da chave privada associada ao username.

### 3.3 PKI com CA self-signed

O servidor atua como Autoridade de Certificação local. A CA emite certificados X.509 que associam usernames a chaves públicas.

A chave privada da CA fica em:

```text
ca_key.pem
```

e é cifrada com password. O certificado público da CA fica em:

```text
ca_cert.pem
```

O certificado da CA deve ser previamente distribuído aos clientes por um canal confiável.

### 3.4 Pinning da CA

O cliente não aceita cegamente a CA enviada pela rede. Antes de se ligar ao servidor, carrega a CA local `ca_cert.pem`. Quando o servidor envia a sua CA, o cliente valida o certificado e compara a fingerprint SHA-256 da CA recebida com a fingerprint da CA local.

Se forem diferentes, a ligação é terminada. Isto protege contra substituição da CA por um atacante man-in-the-middle.

### 3.5 Mensagens de controlo assinadas

Mensagens administrativas enviadas pelo servidor, como `CA_CERT`, `MEU_CERT`, `CERT`, `CHALLENGE`, `INFO` e `GROUP_KEY`, são encapsuladas em mensagens `CTRL` assinadas com a chave privada da CA.

O formato lógico é:

```text
CTRL:<tipo>:<tamanho_payload><payload><assinatura>
```

A assinatura cobre:

```text
SSI-CHAT-v1|SERVER_CTRL|tipo|payload
```

O cliente rejeita mensagens de controlo antigas que cheguem sem assinatura. Esta medida reduz o risco de manipulação de mensagens administrativas por um atacante de rede.

### 3.6 Listagem de utilizadores

O comando:

```text
/listar
```

pede ao servidor a lista de utilizadores online e autenticados. O servidor usa locks ao consultar a estrutura partilhada de clientes, evitando problemas de concorrência entre threads.

### 3.7 Mensagens privadas online

O comando:

```text
/msg <utilizador> <mensagem>
```

envia uma mensagem privada. Se o destinatário estiver online, é usado um handshake X25519 com chaves efémeras para derivar uma chave AES de sessão.

O payload assinado da mensagem privada tem o formato:

```text
destinatario:contador:mensagem
```

Depois de assinado com RSA-PSS, o payload é cifrado com AES-GCM.

### 3.8 Mensagens privadas offline

Se o destinatário estiver offline, o servidor guarda os pacotes cifrados. Para permitir a decifragem posterior, o remetente envia uma chave AES embrulhada com a chave pública RSA do destinatário, usando RSA-OAEP.

Quando o destinatário volta a ligar, o servidor entrega primeiro a chave de sessão embrulhada e depois as mensagens cifradas.

### 3.9 Reconexão de utilizadores

Quando um utilizador reconecta, os outros clientes recebem novamente o seu certificado. Se já existia uma sessão AES anterior com esse utilizador, o cliente encerra a sessão local antiga e limpa contadores e buffers associados. Isto evita tentar reutilizar uma sessão antiga depois de uma reconexão.

### 3.10 Mensagens de grupo

Foram implementados chats multi-utilizador com comandos:

```text
/grupo criar <grupo> <membro1> <membro2> ...
/grupo msg <grupo> <mensagem>
/grupo membros <grupo>
```

O criador é automaticamente incluído no grupo.

Cada grupo tem uma chave AES própria. O criador gera essa chave e envia ao servidor uma versão cifrada individualmente para cada membro, usando RSA-OAEP com a chave pública de cada membro.

O servidor guarda apenas:

- nome do grupo;
- admin;
- lista de membros;
- chave de grupo cifrada para cada membro.

O servidor nunca guarda a chave de grupo em claro.

### 3.11 Mensagens de grupo offline

Se um membro do grupo estiver offline, o servidor guarda a mensagem de grupo cifrada e entrega-a quando esse utilizador voltar a ligar. Ao autenticar-se, o utilizador recebe também as chaves de grupo cifradas para os grupos de que faz parte.

O cliente tem ainda um buffer defensivo para o caso de receber uma `GROUP_MSG` antes da respetiva `GROUP_KEY`.

---

## 4. Fluxos de comunicação

### 4.1 Arranque do servidor

1. Carrega `bd_utilizadores.json`.
2. Carrega `mensagens_offline.json`.
3. Carrega `grupos_chat.json`.
4. Carrega ou gera a CA.
5. Se a CA existir, pede a password da chave privada.
6. Se a CA não existir, gera um novo par e grava `ca_key.pem` cifrado.
7. Inicia escuta em `127.0.0.1:65432`.

### 4.2 Arranque do cliente

1. Carrega `ca_cert.pem`.
2. Valida se é uma CA self-signed válida.
3. Mostra a fingerprint SHA-256.
4. Pede o username.
5. Valida o username.
6. Carrega ou gera a identidade RSA.
7. Liga ao servidor.
8. Envia `KEY:<username>:<public_key>`.

### 4.3 Autenticação

```text
Cliente -> Servidor: KEY:<username>:<public_key>
Servidor -> Cliente: CTRL:CHALLENGE:<desafio>
Cliente -> Servidor: RESPONSE:<assinatura_do_desafio>
Servidor: verifica assinatura
```

Depois da autenticação, o servidor emite o certificado do cliente e envia a CA e certificados relevantes.

### 4.4 Handshake privado online

Quando Alice quer comunicar com Bob online, é criado um segredo de sessão através de um handshake X25519 com chaves efémeras. A chave AES final nunca é transmitida pela rede: é derivada localmente pelos dois clientes a partir do segredo X25519 e do mesmo contexto público no HKDF.

1. Alice gera um par de chaves efémero X25519:

```text
priv_efemera_Alice, pub_efemera_Alice
```

2. Alice constrói e assina o payload de início de sessão:

```text
SSI-CHAT-v1|SESSION_INIT|Alice|Bob|pub_efemera_Alice
```

Esta assinatura liga a chave efémera ao remetente, ao destinatário e ao tipo de mensagem, evitando reutilização da assinatura noutro contexto.

3. Alice envia `SESSION_INIT` para Bob através do servidor.

4. Bob verifica a assinatura de Alice usando a chave pública certificada de Alice.

5. Bob gera o seu próprio par de chaves efémero X25519:

```text
priv_efemera_Bob, pub_efemera_Bob
```

6. Bob constrói o contexto público usado no HKDF:

```text
SSI-CHAT-v1|HKDF|Alice|Bob|pub_efemera_Alice|pub_efemera_Bob
```

7. Bob deriva a chave AES da sessão usando a sua chave privada efémera, a chave pública efémera de Alice e o contexto HKDF:

```python
chave_aes = derivar_chave_aes(
    priv_efemera_Bob,
    pub_efemera_Alice,
    contexto_hkdf
)
```

8. Bob constrói e assina o payload de resposta:

```text
SSI-CHAT-v1|SESSION_ACK|Bob|Alice|pub_efemera_Alice|pub_efemera_Bob
```

A resposta inclui as duas chaves efémeras, garantindo que o ACK está ligado ao INIT que lhe deu origem.

9. Bob envia `SESSION_ACK` para Alice através do servidor.

10. Alice verifica a assinatura de Bob usando a chave pública certificada de Bob.

11. Alice constrói o mesmo contexto HKDF:

```text
SSI-CHAT-v1|HKDF|Alice|Bob|pub_efemera_Alice|pub_efemera_Bob
```

12. Alice deriva a mesma chave AES usando a sua chave privada efémera, a chave pública efémera de Bob e o mesmo contexto:

```python
chave_aes = derivar_chave_aes(
    priv_efemera_Alice,
    pub_efemera_Bob,
    contexto_hkdf
)
```

Como a operação X25519 produz o mesmo segredo partilhado dos dois lados, e ambos usam o mesmo contexto no HKDF, Alice e Bob chegam à mesma chave AES sem que essa chave seja alguma vez transmitida pela rede.

### 4.5 Envio de mensagem privada

1. O cliente constrói `destinatario:contador:mensagem`.
2. Assina com RSA-PSS.
3. Junta payload + assinatura.
4. Cifra com AES-GCM.
5. Envia `nonce || ciphertext`.
6. O servidor encaminha.
7. O destinatário decifra, verifica assinatura, verifica destinatário e contador.

### 4.6 Criação de grupo

1. Alice executa:

```text
/grupo criar amigos Bob Carol
```

2. Alice gera uma chave AES aleatória para o grupo.
3. Alice cifra essa chave individualmente para Alice, Bob e Carol.
4. Alice envia a lista de membros e as chaves cifradas ao servidor.
5. O servidor guarda o grupo e envia a cada membro online a sua `GROUP_KEY` assinada como mensagem de controlo.
6. Membros offline recebem a `GROUP_KEY` ao voltar a ligar.

### 4.7 Mensagem de grupo

1. O remetente constrói:

```text
GROUP:<grupo>:<remetente>:<contador>:<mensagem>
```

2. Assina esse payload com RSA-PSS.
3. Cifra payload + assinatura com AES-GCM usando a chave do grupo.
4. Envia ao servidor.
5. O servidor encaminha para membros online e guarda para membros offline.
6. Cada recetor decifra, verifica assinatura, confirma membership, confirma grupo/remetente e valida contador anti-replay.

---

## 5. Gestão de chaves

### 5.1 Chaves RSA dos utilizadores

As chaves RSA dos utilizadores são chaves de identidade persistentes. São usadas para:

- provar posse da identidade no challenge-response;
- assinar mensagens privadas e de grupo;
- verificar autenticidade de remetentes;
- embrulhar chaves AES offline e chaves de grupo.

### 5.2 Chave da CA

A chave privada da CA é a raiz de confiança do sistema. É protegida com password e permissões restritivas. Se apenas um dos ficheiros `ca_key.pem` ou `ca_cert.pem` existir, o servidor aborta para evitar inconsistência da raiz de confiança.

### 5.3 Chaves de sessão online

Nas conversas privadas online, a chave AES é derivada a partir de X25519 efémero. Esta abordagem dá forward secrecy parcial: comprometer mais tarde a chave RSA de identidade não basta para decifrar mensagens online antigas, desde que as chaves efémeras tenham sido descartadas.

### 5.4 Chaves offline

Mensagens offline privadas usam uma chave AES embrulhada com RSA-OAEP. Isto permite entrega assíncrona, mas não dá forward secrecy forte para mensagens offline.

### 5.5 Chaves de grupo

Cada grupo tem uma chave AES partilhada pelos seus membros. A chave é distribuída cifrada individualmente para cada membro com RSA-OAEP. A composição dos grupos é fixa após a criação.

---

## 6. Primitivas criptográficas

### 6.1 AES-GCM

Usado para cifragem autenticada das mensagens privadas e de grupo. Cada mensagem usa nonce aleatório de 12 bytes.

### 6.2 RSA-PSS

Usado para assinaturas digitais em:

- challenge-response;
- mensagens privadas;
- mensagens de grupo;
- handshake X25519;
- mensagens de controlo do servidor.

### 6.3 RSA-OAEP

Usado para transportar chaves AES de forma segura em cenários offline e na distribuição de chaves de grupo.

### 6.4 X25519

Usado para acordo de chaves efémero entre dois utilizadores online.

### 6.5 HKDF-SHA256

Usado para derivar uma chave AES de 256 bits a partir do segredo X25519, incluindo contexto do protocolo no campo `info`.

### 6.6 X.509

Usado para associar usernames a chaves públicas através de certificados emitidos pela CA local.

---

## 7. Modelo de segurança

### 7.1 Ativos protegidos

O sistema procura proteger:

- conteúdo das mensagens privadas;
- conteúdo das mensagens de grupo;
- integridade das mensagens;
- autenticidade dos remetentes;
- identidade criptográfica dos utilizadores;
- chaves privadas locais;
- mensagens offline guardadas no servidor;
- chaves de grupo.

### 7.2 Capacidades do atacante

Considera-se que o atacante pode:

- observar a rede;
- tentar modificar pacotes;
- tentar reenviar mensagens antigas;
- tentar substituir a CA;
- tentar criar usernames maliciosos;
- tentar usurpar uma identidade existente;
- tentar enviar pacotes demasiado grandes;
- tentar encaminhar mensagens para destinatários/grupos diferentes.

### 7.3 Garantias

#### Confidencialidade

As mensagens são cifradas no cliente com AES-GCM antes de chegarem ao servidor. O servidor guarda e encaminha apenas ciphertexts.

#### Integridade

AES-GCM deteta alterações no ciphertext. Além disso, o conteúdo lógico da mensagem é assinado com RSA-PSS.

#### Autenticidade

A autenticidade é fornecida por:

- certificados X.509;
- challenge-response;
- assinaturas RSA-PSS nas mensagens;
- assinaturas contextuais no handshake;
- assinatura das mensagens de controlo do servidor.

#### Proteção contra MITM

A CA é validada por pinning/fingerprint. Assim, um atacante não deve conseguir trocar a raiz de confiança sem ser detetado.

#### Proteção contra replay

Mensagens privadas e de grupo usam contadores monotónicos. Contadores repetidos ou inferiores ao último valor aceite são rejeitados.

#### Proteção contra forwarding

Mensagens privadas incluem o destinatário no payload assinado. Mensagens de grupo incluem grupo e remetente. Isto impede reutilizar uma mensagem válida noutro contexto sem ser detetado.

#### Controlo de acesso em grupos

Só membros recebem a chave AES do grupo. O servidor também verifica se o remetente pertence ao grupo antes de encaminhar uma `GROUP_MSG`. No cliente, a mensagem só é aceite se o remetente fizer parte da lista local de membros do grupo e a assinatura for válida.

---

## 8. Robustez de implementação

Foram adicionadas medidas para reduzir erros de implementação:

- validação centralizada de usernames e grupos;
- limite máximo de pacotes em `rede.py`;
- limite de texto no cliente;
- locks para estruturas partilhadas no servidor;
- rejeição de pacotes malformados;
- permissões restritivas nos ficheiros sensíveis;
- `.gitignore` para evitar versionar chaves, certificados e dados de runtime;
- modularização do código por responsabilidade;
- buffer defensivo para mensagens privadas ou de grupo que cheguem antes da respetiva chave.

---

## 9. Limitações

### 9.1 Segurança não absoluta

A solução foi desenhada para o modelo de atacante definido, mas não pretende ser equivalente a uma aplicação de mensagens de produção.

### 9.2 Forward secrecy parcial

Há forward secrecy para sessões privadas online baseadas em X25519. Mensagens offline e mensagens de grupo não têm forward secrecy forte.

### 9.3 Sem Double Ratchet

Não existe rotação de chave por mensagem como no Signal. Dentro de uma sessão ou grupo, uma chave pode proteger várias mensagens.


### 9.4 Grupos com composição fixa

A adição e remoção dinâmica de membros não foi implementada. Para remover membros corretamente seria necessário gerar uma nova chave de grupo e redistribuí-la aos membros restantes. Para adicionar membros sem revelar mensagens antigas, também seria necessário rekeying e versionamento de chaves.

### 9.5 Sem revogação de certificados

Não há CRL/OCSP nem mecanismo formal de revogação. Se uma chave privada for comprometida, o sistema não tem ainda uma forma automática de invalidar o certificado.

### 9.6 Sem TLS real

A solução implementa autenticação e proteção ao nível da aplicação. Num sistema real, seria recomendável usar TLS autenticado entre cliente e servidor e manter E2EE por cima.

### 9.7 Comandos cliente-servidor não são todos assinados individualmente

O servidor autentica a ligação por challenge-response e assina as mensagens de controlo enviadas ao cliente. Ainda assim, alguns comandos administrativos enviados do cliente para o servidor dependem da sessão TCP autenticada no servidor e não têm assinatura própria por mensagem. Uma versão futura poderia assinar também comandos como `GROUP_CREATE` e `/listar`.

---

## 10. Testes realizados

Foram testados manualmente:

- compilação dos ficheiros Python;
- geração da CA;
- carregamento da CA existente;
- proteção de `ca_key.pem` com password;
- rejeição de password errada da CA;
- criação de Alice, Bob e Carol;
- carregamento de identidades existentes;
- rejeição de password errada de utilizador;
- validação da CA por fingerprint;
- rejeição de CA diferente;
- autenticação por challenge-response;
- rejeição de usernames inválidos;
- `/listar`;
- mensagens privadas online;
- mensagens privadas offline;
- entrega offline após reconexão;
- limpeza de sessão antiga após reconexão;
- criação de grupos;
- listagem de membros de grupos;
- mensagens de grupo online;
- mensagens de grupo com membros offline;
- persistência de grupos após reinício do servidor;
- rejeição de mensagens para grupos inexistentes;
- rejeição de envio por não-membros;
- limites de tamanho de mensagens.

---

## 11. Relação com os requisitos do enunciado

| Requisito/valorização | Estado |
|---|---:|
| Arquitetura cliente-servidor | Implementado |
| Comandos textuais no cliente | Implementado |
| E2EE | Implementado |
| Confidencialidade | Implementado |
| Integridade | Implementado |
| Autenticidade | Implementado |
| Servidor honesto mas curioso | Considerado |
| Resistência a MITM | Implementada por pinning da CA e assinaturas |
| `cryptography` | Usada |
| Gestão de chaves | Documentada |
| Mensagens offline | Implementado |
| PKI/CA self-signed | Implementado |
| Mensagens de grupo | Implementado |
| Forward secrecy | Parcial, em sessões privadas online |
| Relatório Markdown | Implementado |

---

## 12. Melhorias futuras

- Implementar rotação de chaves por mensagem.
- Adicionar revogação de certificados.
- Implementar adição/remoção dinâmica de membros em grupos com rekeying.
- Assinar individualmente comandos cliente-servidor sensíveis.
- Usar TLS autenticado entre cliente e servidor.
- Definir política formal para múltiplas sessões do mesmo utilizador.

---

## 13. Conclusão

A solução final implementa um chat seguro com E2EE, autenticação criptográfica de utilizadores, PKI local, pinning da CA, mensagens offline, mensagens de grupo, proteção contra replay e validação de mensagens de controlo do servidor.

O servidor continua a desempenhar um papel central de coordenação, mas não tem acesso ao conteúdo em claro das mensagens privadas ou de grupo. A solução não é perfeita nem pretende substituir um protocolo de produção, mas cobre os requisitos principais do enunciado e várias valorizações relevantes, mantendo as limitações documentadas de forma explícita.
