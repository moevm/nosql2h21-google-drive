# nosql2h21-google-drive

## Hello world

Порядок запуска:

1. Убеждаемся, что mongod (демон СУБД называется mongod, не mongodb) запущен (например, `pgrep -a mongod`, или если есть сервис systemd, `systemctl status mongod`)

2. Убеждаемся, что мы активировали виртуальное окружение и что в нём установлены все пакеты. Пример как это всё сделать в первый раз (виртуальное окружение будет в каталоге venv):

   ```sh
   python3 -m venv venv
   source venv/bin/activate
   pip3 install -r requirements.txt
   ```

3. Загружаем тестовые данные в БД:

   ```sh
   cat misc/data.mongo | mongoimport -d helloworld -c messages
   ```

4. Для запуска скрипта:

   ```sh
   ./hello-world.py
   ```

   На 127.0.0.1:8080 запустится веб-сервер. Страничка по ссылке "Hello world" должна выдавать сообщение, записанное в БД, а страничка по ссылке "Hello mongo" должна выдавать ошибку (т.к. соответствующего документа нет в БД).
