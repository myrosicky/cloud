FROM tomcat:9.0.30
MAINTAINER "myrosicky"
ARG BUILD_FILE
ADD src/main/docker/ /usr/local/tomcat/conf/
ADD target/${BUILD_FILE} /usr/local/tomcat/webapps/
