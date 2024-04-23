@ECHO off

ECHO.
ECHO :::::::::::::::::::::: Compilation ^& jar export ::::::::::::::::::::::::::
ECHO ::                                                                      ::
ECHO :: By:      SegC-24, 2024-04-22                                         ::
ECHO :: Version: 1.1                                                         ::
ECHO :: Purpose: Compile the project to class and export the jar             ::
ECHO :: Origin:  https://stackoverflow.com/a/17932145                        ::
ECHO :: Colors:  https://stackoverflow.com/a/38617204                        ::
ECHO ::                                                                      ::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::


javac ./IoTDevice.java
jar -cfe IoTDevice.jar IoTDevice *.class

javac ./IoTServer.java
jar -cfe IoTServer.jar IoTServer *.class

ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO :: Finished                                                             ::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::