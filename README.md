Trabalho 1 - Fase 2 de Segurança e Confiabilidade realizado por Manuel Campos (58166), Tiago Almeida (58161) e Tiago Rocha (58242).

Projeto realizado a 100%, todas as funcionalidades e verificações pedidas foram implementadas, todos os dados estão persistentes, guião 100% realizado.

--------------------------------------------------------------------------------------------------------------------

COMO CORRER E COMPILAR:

COMPILE:
    1 - Compilar o server com <makefile.bat>

    2 - Compilar o client com <makefile.bat>

    3 - Copiar o IoTDevice.jar do lado do server e mudar o nome para IoTDeviceCopy.jar

RUN:
    1 - Correr o server: <java IoTServer [porto] [password-cifra] [keystore] [password-keystore] [2FA-APIKey]>
        porto -> Escolha livre
        password-cifra -> Escolha livre
        keystore -> "svStore"
        password-keystore -> "grupoquinze"
        2FA-APIKey (grupo15) -> "zWG5VYlpX9NwOWLvUqn1"

        (ex: java -jar IoTServer.jar 1234 grupoquinze svStor )

    2 - Correr o client: <java IoTDevice [ip:porto] [trust-store] [keystore] [password-keystore] [dev-id] [user-id]>
        ip:porto -> Ip e porto do server
        truststore -> "cliTrustStore"
        keystore -> 3 opções válidas que são os nossos users -> "tiagoStore" | "manelStore" | "rochaStore" (TAMBÉM PODERÁ SER CRIADO UM NOVO USER -> Ver "COMO CRIAR UM NOVO USER")
        password-keystore -> "grupoquinze" (keystores pré-definidas) / password escolhida na criação do novo user
        dev-id -> Escolha livre
        user-id -> 3 opções válidas que são os nossos users (terá de ter acesso aos mails) -> "tjca2000@gmail.com" | "mgacampos10@gmail.com" | "tiago.laureano.rocha@gmail.com" (TAMBÉM PODERÁ SER CRIADO UM NOVO USER -> Ver "COMO CRIAR UM NOVO USER")

        (ex: java -jar IoTDevice.jar 127.0.0.1:1234 cliTrustStore manelStore grupoquinze 5 mgacampos10@gmail.com )

Após estes comandos já se pode utilizar o menu presente no Cliente que comunicará com o servidor para transmitir dados e comandos!

--------------------------------------------------------------------------------------------------------------------

COMO CRIAR UM NOVO USER (Device do cliente):
    keytool -genkeypair -alias <alias> -keyalg RSA -keysize 2048 -storetype JCEKS -keystore <nome_store>
    keytool -exportcert -alias <alias> -storetype JCEKS -keystore <nome_store> -file <nome_certificado.cer>
    keytool -importcert -alias <alias> -file <nome_certificado.cer> -storetype JCEKS -keystore <cliTrustStore>
        
        <alias> -> Deve ser a substring do email associado até ao @
        <nome_store> -> Escolha livre
        <nome_certificado.cer> -> Escolha livre + .cer

--------------------------------------------------------------------------------------------------------------------

INFORMAÇÕES RELATIVAS A FICHEIROS .txt:

1 - Após iniciar o servidor, vários ficheiros de texto irão ser criados (a não ser que os mesmos já existam previamente):
    (TODOS OS DADOS ESTÃO GUARDADOS DE FORMA PERSISTENTE)

    1.1 - Pasta txtFiles:
        clientProgram.txt --> Ficheiro que guarda o path da cópia do IoTDevice.jar presente no server (executável)

        domainsInfo.txt --> Ficheiro que guarda informações sobre os dominios e: os respetivos users, devices, bem como o seu criador

        domainsInfoHMAC.txt --> Ficheiro que guarda o último HMAC calculado do ficheiro domainsInfo.txt

        lastParams.txt --> Ficheiro que guarda os parâmetros usados na última encriptação feita do ficheiro users.txt com o "PBEWithHmacSHA256AndAES_128"

        progDataHMAC.txt --> Ficheiro que guarda o último HMAC calculado do ficheiro clientProgram.txt

        registeredDevices.txt --> Ficheiro que guarda os devices que já se autenticaram pela primeira vez no servidor

        svSalt.txt --> Ficheiro que guarda o salt que virá a ser utilizado na cifra do users.txt e no cálculo do HMAC do clientProgram.txt e domainsInfo.txt

        users.txt --> Ficheiro que guarda os users existentes em formato <user-id>:<nome do ficheiro de certificado com a chave pública> (CIFRADO)

    1.2 - Pasta domKeys:
        Cada file .txt da pasta corresponde a uma key de domain cifrada associada a um domain e a um user, com o nome com formato <domainName_userId>

    1.3 - Pasta imgFiles:
        Cada file .txt da pasta corresponde a uma imagem cifrada correspondente a um domain e a um device, com o nome no formato <userId_devId_domainName>

    1.4 - Pasta imgParams:
        Cada file .txt da pasta corresponde aos parâmetros usados para cifrar uma imagem, e que vão ser usados para a decifrar, com o nome no formato <userId_devId_domainName>

    1.5 - Pasta tempFiles:
        Cada file .txt da pasta corresponde a uma temperatura cifrada correspondente a um domain e a um device, com o nome no formato <userId_devId_domainName>

    1.6 - Pasta tempParams:
        Cada file .txt da pasta corresponde aos parâmetros usados para cifrar uma temperatura, e que vão ser usados para a decifrar, com o nome no formato <userId_devId_domainName>


2 - Quando o owner adiciona um user a um domain pela primeira vez, cada salt usado na criação das chaves é guardado num ficheiro único por chave .txt exclusivo do user com o nome <salt_userId_domainName>
    Quando o owner adiciona um user a um domain pela primeira vez, o número de iterações usado na criação da chave é adicionado a um ficheiro .txt exclusivo do user com o nome <iters_userId>


3 - Persistência: O projeto dispõe de <Volatile & Locks> para não comprometer a thread safety.


4 - RI: A imagem do device retornada pelo comando é guardada em formato .jpg com o nome <requestedUserId_requestedDevId_received>

--------------------------------------------------------------------------------------------------------------------

FICHEIROS KEYSTORE E CERTIFICADOS (Users e servidor):

Keystores (Todas as passwords são "grupoquinze"):
    Server -> svStore
    User tjca2000@gmail.com -> tiagoStore
    User mgacampos10@gmail.com -> manelStore
    User tiago.laureano.rocha@gmail.com -> rochaStore

TrustStore (Password é "grupoquinze"): 
    cliTrustStore

Certificados:
    Server -> svCert.cer
    User tjca2000@gmail.com -> tiagoCert.cer
    User mgacampos10@gmail.com -> manelCert.cer
    User tiago.laureano.rocha@gmail.com -> rochaCert.cer

ALIAS DE CADA KEY NAS KEYSTORES: Substring do email até ao @ (ex. "tjca2000@gmail.com" seria "tjca2000")
ALIAS DE CADA CERTIFICADO NA TRUSTSTORE: Substring do email até ao @ (ex. "tjca2000@gmail.com" seria "tjca2000")

OBS: O código está desginado para funcionar em pleno com os 3 emails/users pré-definidos. Para utilizar outro email, ver secção "COMO CRIAR UM NOVO USER".