#!/bin/bash
home_dir=/home/redza/ext4_dir
sudo find "$home_dir" -mindepth 1 ! -name "lost+found" -exec rm -rf {} +
sudo dd if=/dev/zero of=${home_dir}/test bs=1024 count=2000 status=none
for i in {1..900}; do
	sudo cp ${home_dir}/test ${home_dir}/test_$i
	if (($i % 100 == 0)); then
		echo "$i files copied..."
	fi
done
echo "ext4 test copying complete!"

