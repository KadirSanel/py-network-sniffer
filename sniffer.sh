#!/usr/bin/env bash


if [ "$1" == "build" ]
then
    docker image build -t pysniff:1.0.0 .
fi

if [ "$1" == "sniff" ]
then
    docker run pysniff:1.0.0
fi

