FROM centos:centos7
ENV container=docker

RUN yum -y update
RUN yum makecache fast
RUN yum install -y nc
RUN yum install -y net-tools
RUN yum install -y tcpdump
RUN yum install -y java-1.8.0-openjdk 
RUN yum install -y java-1.8.0-openjdk-devel
RUN yum install -y zip
RUN yum install -y unzip
RUN yum install -y mtr

ENV UNBOUNDID_HOME /opt/unboundid-ldap
ENV UNBOUNDID_VERSION unboundid-ldapsdk-3.1.0-se

ADD https://docs.ldap.com/ldap-sdk/files/${UNBOUNDID_VERSION}.zip unboundid-ldapsdk-se.zip
RUN mkdir -p ${UNBOUNDID_HOME}
ADD ildap.ldif /opt/unboundid-ldap/ldap.ldif
RUN unzip unboundid-ldapsdk-se.zip -d ${UNBOUNDID_HOME}

ENTRYPOINT ./${UNBOUNDID_HOME}/${UNBOUNDID_VERSION}/tools/in-memory-directory-server \
    --baseDN 'o=INTLDAP' \
    --port 389 \
    --ldifFile /opt/unboundid-ldap/ldap.ldif \
    --accessLogToStandardOut 

EXPOSE 389
