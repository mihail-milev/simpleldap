#!/bin/bash

container=$(buildah from docker.io/fedora:35)
mountpoint=$(buildah mount $container)

cp ./target/release/simpleldap $mountpoint/simpleldap
cp ./database.sqlite $mountpoint/database.sqlite

buildah config --entrypoint "/simpleldap" $container
buildah config --user 1000:1000 $container

buildah commit --format docker $container simpleldap

buildah unmount $container