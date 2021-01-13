#!/bin/sh
#

export VERSION=0.1

case "$1" in
	jar)
	./gradlew build
	;;

	aar)
	cd android && ./gradlew build
	;;

	*)
	echo "Unknown build target. Valid targets are: jar or aar"
	;;
esac
