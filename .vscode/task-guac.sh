mvn clean compile assembly:single \
    && cp -v target/dataprovider-yml-1.0-SNAPSHOT-jar-with-dependencies.jar data/home/extensions/data-provider.jar \
    && sudo CATALINA_HOME=/usr/share/tomcat9 CATALINA_BASE=/var/lib/tomcat9 CATALINA_TMPDIR=/tmp JAVA_OPTS=-Djava.awt.headless=true /bin/sh /usr/libexec/tomcat9/tomcat-start.sh
