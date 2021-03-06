#!/bin/bash
if [[ $1 == '--production' ]]; then
    npm install --production
    rm -rf node_modules/@f5devcentral
fi

tar -C .. --exclude=".git*" --exclude="test" --exclude="${PWD##*/}/dist" --exclude="build" --exclude="doc" --exclude="gitHooks" -cf dist/f5-cloud-libs-aws.tar f5-cloud-libs-aws

# Suppress gzips timetamp in the tarball - otherwise the digest hash changes on each
# commit even if the contents do not change. This causes an infinite loop in the build scripts
# due to packages triggering each other to uptdate hashes.
gzip -nf dist/f5-cloud-libs-aws.tar
