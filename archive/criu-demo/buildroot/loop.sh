$ cat > test.sh <<-EOF
#!/bin/sh
while :; do
    sleep 1
    date
done
EOF
$ chmod +x test.sh
