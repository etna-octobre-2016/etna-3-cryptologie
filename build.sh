#!/bin/sh
javac -d class -cp lib/commons-lang3-3.4.jar:src src/main.java && java -cp lib/commons-lang3-3.4.jar:class Main
