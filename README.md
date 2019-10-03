How to play:

1) Create the env.list file and specify your credentials there:
```
LOGIN=xxxxx             # must be 5 digits, can be found here https://my.selectel.ru/storage/users
PASSWORD=xxxxxx
STORAGE=xxxxxx          # must be 6 digits
```

2) Build the image from the Dockerfile
```
sudo docker build -t selectel_loader .
```

3) Run the container in the interactive mode:
```
sudo docker run --env-file env.list -i -v [local directory]:/selectel/shared selectel_loader -i
```
Here the "-i" option means that you want to enter several commands interactively. 
In the interactive mode you should simply type "-g" if you want the files list, or "-u file"
to upload the file. Also you can pass these options in the one-command mode, in the same way as "-i" above.

The full help:
```
docker run --env-file env.list -i -v [local directory]:/selectel/shared \
        [container name] [-c [file1 [file2 ...]]] [-d [file1 [file2 ...]]] \
        [-g [dir]] [--ls [dir]] [-r [file1 [file2 ...]]] [-t dir] \
        [-u [file1 [file2 ...]]] [-e] [-f] [-h] [-i] [-m] [-q] [-s] [-z]

  -c [file1 [file2 ...]], --check [file1 [file2 ...]]
                        check if the file is in the container
  -d [file1 [file2 ...]], --download [file1 [file2 ...]]
                        download files
  -g [dir], --get-list [dir]
                        get the list of files in the container or in the given
                        directory
  --ls [dir]            get the list of files in the local storage or in the
                        given directory
  -r [file1 [file2 ...]], --remove [file1 [file2 ...]]
                        remove files
  -t dir, --to-dir dir  create a local directory to download file into it or
                        create a remote directory to upload file
  -u [file1 [file2 ...]], --upload [file1 [file2 ...]]
                        upload files
  -e, --extract         upload and extract the .tar, .tar.gz or .gzip archive
                        into the container
  -f, --force           force upload files
  -h, --help            show this help message
  -i, --interactive     enter interactive mode to run multiple commands
  -m, --minimize        hide the subdirectories contents
  -s, --switch          switch to another container
  -q, --quit            leave interactive mode and exit
  -z, --zip             download file/directory as an archive
```