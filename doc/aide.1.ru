.TH "aide" "1"
.SH "НАЗВАНИЕ"
\fBaide\fP \- Advanced Intrusion Detection Environment
.SH "СИНТАКСИС"
\fBaide\fP
\%[\fBoptions\fP]
\%\fBcommand\fP
.SH "ОПИСАНИЕ"
\fBaide\fP это система определения незаконных вторжений в систему, путем проверки целостности файловой системы

.SH "КОМАНДЫ"
.PP
.IP --check, -C
Проверяет базу на непоследовательноть данных. Вы должны предварительно
создать базу перед данной процедурой. Это также действие по умолчанию.
Запущенная безо всяких параметров программа \fBaide\fP будет выполнять проверку.
.IP --init, -i
Создает базу данных. Вы должны создать базу и скопировать ее в определенное
место паред использованием параметра --check.
.IP --update, -u
Проверяет базу и вносит обновления, если это необходимо, автоматически.
Входная и вызодная базы должны быть различны.
.SH "ПАРАМЕТРЫ"
.IP --config=\fBconfigfile\fR , -c \fBconfigfile\fR
Конфигурационные данные будут прочитаны из файла\fBconfigfile\fR вместо "./aide.conf". Можно использовать '-' для обозначения стандартного входа
.IP --before="\fBconfigparameters\fR" , -B "\fBconfigparameters\fR"
Этот параметр означает что надо принять \fBconfigparameters\fR перед
чтением конфигурационного файла. Смотрите aide.conf (5)
для более подробной информации о том, что можно поместить здесь.
.IP --after="configparameters" , -A "configparameters"
Этот параметр означает что надо принять \fBconfigparameters\fR после
чтения конфигурационного файла. Смотрите aide.conf (5)
для более подробной информации о том, что можно поместить здесь.
.IP --verbose=verbosity_level,-Vverbosity_level
Контролирует уровень подробности сообщений \fBaide\fP. Значение должно быть между 0 и 255.
По умолчанию оно принимается равным 5. Без параметра значение устанавливается в 20.
Этот параметр изменяет значение заданное в конфигурационном файле.
.IP --report=\fBreporter\fR,-r \fBreporter\fR
\fBreporter\fR это URL который указывает \fBaide\fP куда ей отсылать весь вывод.
Смотрите aide.conf (5), раздел URL  на предмет допустимых значений.
.IP --version,-v
\fBaide\fP выводит номер версии.
.IP --help,-h
Выводит стандартное мправочное сообщение.
.PP
.SH "ФАЙЛЫ"
.B <prefix>/etc/aide.conf
Стандартный конфигурационный файл aide.
.B <prefix>/etc/aide.db
Стандартная база данных aide.
.B <prefix>/etc/aide.db.new
Стандартная выходная (вновь создаваемая) база aide.
.SH "СМ. ТАКЖЕ"
.BR aide.conf (5)
.BR http://www.cs.tut.fi/~rammer/aide/manual.html
.SH "ОШИБКИ"
В этой версии программы возможно наличие ошибок. Пожайлуста сообщите о них
rammer@cs.tut.fi. Исправления приветствуются. Предпочитаются в виде стандартных патчей.
.SH DISCLAIMER
All trademarks are the property of their respective owners.
No animals were harmed while making this webpage or this piece of
software. Although some pizza delivery guy's feelings were hurt.
.BR
.SH "ПЕРЕВОД"
Translation by Stanislav I. Ievlev <inger@linux.ru.net>
