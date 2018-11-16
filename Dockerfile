FROM jvdmr/apache-dev
MAINTAINER @jvdmr

EXPOSE 80

ADD . /opt/jvdmr/apache2/mod_evasive
WORKDIR /opt/jvdmr/apache2/mod_evasive

RUN mv mod_evasive24.c mod_evasive.c && \
    /usr/bin/apxs -i -a -c mod_evasive.c && \
		apache2ctl configtest

RUN cp mod_evasive.conf /etc/apache2/conf-enabled/mod_evasive.conf

CMD service apache2 start && bash
