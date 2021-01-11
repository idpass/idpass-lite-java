#!/bin/sh
#

export VERSION=0.1

case "$1" in
	java)
	./gradlew build
	;;

	android)
	cd android && ./gradlew build
	;;

	*)
	echo "Unknown build target. Valid targets are: java or android"
	;;
esac
