FROM daocloud.io/daocloud/dao-tomcat:v7.0.55 
MAINTAINER "myrosicky"
ARG BUILD_FILE
ADD src/main/docker/ /tomcat/conf/
ADD target/${BUILD_FILE} /tomcat/webapps/
