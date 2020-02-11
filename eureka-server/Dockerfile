FROM tomcat:jdk8-openjdk
MAINTAINER "myrosicky"
ARG BUILD_FILE
ADD src/main/docker/ /tomcat/conf/
ADD target/${BUILD_FILE} /tomcat/webapps/
