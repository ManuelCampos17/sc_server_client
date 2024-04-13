Projeto 1.1 de Segurança e Confiabilidade realizado por Manuel Campos 58166; Tiago Almeida 58161 & Tiago Rocha 58242

Projeto realizado a 100%.
--------------------------------------------------------------------------------------------------------------------
RUN:

Compilar Com <javac IoTServer.java> & <Javac IoTDevice.java>

Correr 1º o Servidor: <java IoTServer [porto]> sendo o porto opcional

Correr depois os clientes <java IoTClient <serverAddress> <device Id> <UserId> >

Após estes comandos já se pode utilizar o menu presente no Cliente que comunicará com o servidor para transmitir dados e comandos!

--------------------------------------------------------------------------------------------------------------------

Informações adicionais: Após iniciar o servidor, vários ficheiros de texto irão ser criados (a não ser que os mesmos já existam previamente).


clientProgram.txt --> Ficheiro que guarda de forma persistente o <nome do Executável e o seu tamanho> para verificar se o Client tem a versão correta do IoTDevice.

users.txt --> Ficheiro que guarda os users existentes em formato <user>:<password>

domainsInfo.txt --> Ficheiro que guarda informações sobre os dominios e os respetivos <users> que se encontram nos mesmos, guardando também os devices associados a cada dominio. O 1º user que aparece à frente do nome do dominio é o seu Criador/Dono

tempsFile.txt --> Ficheiro que guarda as últimas temperaturas enviadas pelos <users>

registeredDevices.txt --> Ficheiro que guarda os devices que já se autenticaram pela primeira vez


Persistência: <Volatile & Locks> para não comprometer a thread safety.


EI: O comando EI serve para enviar uma imagem do cliente para o servidor. Para facilitar a sua alocação a imagem em formato .jpg irá ter o nome: "user_devid.jpg", assim garantimos que apenas é guardada a última imagem e que a mesma é facilmente identificada.


--------------------------------------------------------------------------------------------------------------------


Keystore: svStore,   svRSA

TrustStore: cliTrustStore,  svCert

Passwords: grupoquinze

Truststore -> cada certificado tem o alias correspondente ao nosso mail até ao @ para ser mais facil o seu mapeamento.

Sempre que for necessário usar um mail novo, temos de criar previamente o mesmo na trusstore como alias do certificado.

Keystore: Alias de cada key é o userid do mail até ao @