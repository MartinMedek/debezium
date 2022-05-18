FROM fedora:35

ARG repository
ARG branch
ARG secret
ARG sdkman_init="/root/.sdkman/bin/sdkman-init.sh"

RUN dnf -y install git unzip zip findutils

RUN curl -s "https://get.sdkman.io" | bash
RUN source $sdkman_init &&\
    sdk install java 17.0.2-open&&\
    sdk install maven

ARG OCP_CLIENT=3.7.23

RUN curl --retry 7 -Lo /tmp/client-tools.tar.gz "https://mirror.openshift.com/pub/openshift-v3/clients/${OCP_CLIENT}/linux/oc.tar.gz"


RUN tar zxf /tmp/client-tools.tar.gz -C /usr/local/bin oc \
    && rm /tmp/client-tools.tar.gz

COPY testsuite-deployment.sh /testsuite/testsuite-deployment.sh
COPY library.sh /testsuite/library.sh
COPY $secret /testsuite/secret.yml

RUN chmod a+x /testsuite/testsuite-deployment.sh


RUN git clone --branch $branch $repository /testsuite/debezium
RUN source $sdkman_init && mvn clean install -DskipTests -DskipITs -f /testsuite/debezium/pom.xml
#
#
##TODO entrypoint = testy
#ENTRYPOINT bash