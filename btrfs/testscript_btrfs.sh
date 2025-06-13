#!/bin/bash
home_dir=/home/redza/btrfs_dir
sudo rm -rf ${home_dir}/*
sudo dd if=/dev/zero of=${home_dir}/test bs=1024 count=2000 status=none
for i in {1..900}; do
	sudo cp --reflink=auto ${home_dir}/test ${home_dir}/test_$i
	if (($i % 100 == 0)); then
		echo "$i files copied..."
	fi
done
echo "btrfs test copying complete!"
