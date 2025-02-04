#!/bin/sh

case $1 in
	join)
		set -x
		exec >hda.bin
		i=0
		while true; do
			file=`printf "hda%09u.bin" $i`
			test -f "$file" || break
			cat -- "$file"  || { rm hda.bin; exit 1; }
			true $((i++))
		done
	;;

	dummy)
		i=48
		while ((i <= 912)) ; do
			file=`printf "hda%09u.bin" $i`;
			dd bs=$((64*1024)) count=0 seek=1 >"$file";
			true $((i++));
		done
	;;      

	mount)
		mkdir -p 0dir
		umount -d 0dir 2>/dev/null
		mount -o loop hda.bin 0dir
	;;

	mount-new*)
		dd if=/dev/zero of=0hda_new.bin bs=1M count=30 || exit 1
		mke2fs -F 0hda_new.bin || exit 1

		mkdir -p 0dir
		umount -d 0dir 2>/dev/null
		mount -o loop 0hda_new.bin 0dir || sleep 5
	;;

	split)
		rm hda0*.bin
		exec <hda.bin
		i=0
		while true; do
			file=`printf "hda%09u.bin" $i`
			dd bs=$((64*1024)) count=1 >"$file" 
			if test "`stat -c '%s' "$file"`" = 0; then
				rm "$file"
				exit 0
			fi
			true $((i++))
		done
	;;	

	umount)
		umount -d 0dir
	;;

esac
