#!/usr/bin/env bash

pushd $(git rev-parse --show-toplevel)

GIT_LFS=$(which git-lfs 2>/dev/null)
if [ -z "$GIT_LFS" ]; then
   echo "git-lfs is not installed"
   echo
   echo "on Mac, you can do a `brew install git-lfs` to add it"
   echo "on Linux, it should be in your package manager as `git-lfs`"

   exit 1
fi

git lfs install --local

git config lfs.customtransfer.tks3.path tkinfra
git config lfs.customtransfer.tks3.args "lfs"
git config lfs.standalonetransferagent tks3
