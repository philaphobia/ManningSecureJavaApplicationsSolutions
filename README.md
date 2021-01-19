# ManningSecureJavaApplications
Solutions for Developing Secure Java Applications for Manning liveProject

This is the companion project for:
https://github.com/philaphobia/ManningSecureJavaApplications

The code is this release contains comments with the solutions. Only review this code if you are interested in the solutions.


## Java version
The program was developed on Java version 1.8, so you should download the latest JRE (and JDK if you want to build) to make sure you can work with the program in Eclipse.

## Application server
The program was developed and tested with Apache Tomcat 8.5. If you plan on deploying and testing the (app not required for the project), make sure you have the latest version of Tomcat 8.5. The webapp was
 tested with a default Apache Tomcat and can simply be deployed by copying the WAR/SecureCoding.war file to the webapps directory under the Tomcat directory.

## Folder structure is as follows:
   * lib - additional libraries needed to build webapp
   * src - source code
   * WAR - compiled .war file to deploy to Tomcat or for scanning
   * WebContent - webapp (.war) file content
   * .classpath - Eclipse classpath
   * .project - Eclipse project file
   * .settings - Eclipse settings folder
   
## Help with Eclipse
Many Integrated Development Environment (IDE) tools are available for coding in Java, so pick the one you have used before. For this project, we use Eclipse. A resource link is provided below if you are interested in learning the basic workflow of how to use Eclipse. You will need the Java EE version of Eclipse to open the project. Import the project into Eclipse. If the project complains about the JRE library, you can following these steps to fix the issue:
* Right-click the lab and choose properties
* Go to Java Build Path
* Click the Libraries tab
* Click add Library
* Choose JRE System Library
* Select Workspace default

## For further reading
These are resources not referenced in the liveProject but may be helpful to further your understanding of the liveProject's content.

* Eclipse IDE Tutorial - (https://www.tutorialspoint.com/eclipse/)
* Download Eclipse IDE for Enterprise Java Developers (https://www.eclipse.org/downloads/packages/)
