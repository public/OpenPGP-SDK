#!/bin/sh

# Make a GPG keyring for testing purposes...

rm -f ../testdata/t1.pub ../testdata/t1.sec

gpg --gen-key --batch <<EOF
#%dry-run
%pubring ../testdata/t1.pub
%secring ../testdata/t1.sec
Key-Type: rsa
Name-Real: OPS Test
Name-Comment: This is a test
Name-Email: ops@links.org
%commit
EOF
