## About
sigtrace is a Linux tool that captures signals (using ptrace) send to a target process
and provides information about the signal sending process. Additionally it is
possible to block signals from being passed to the target process.

The following snippet provides an example of the output:
```
$ ./sigtrace /bin/cat
Got SIGTERM (15) with uid 1000
  21082 bash [/bin/bash]
          /bin/bash 

  21075 /usr/bin/termin [/usr/bin/python2.7]
          /usr/bin/python /usr/bin/terminator 

    866 openbox [/usr/bin/openbox]
          /usr/bin/openbox --startup /usr/lib/x86_64-linux-gnu/openbox-autostart OPENBOX 

    858 lightdm
          lightdm --session-child 13 16 

    817 lightdm
          /usr/sbin/lightdm 

      1 systemd
          /sbin/init 
```

In this case SIGTERM was received from process 21082 (bash)
with the following information being the parent processes of 21082.


## Compiling

Simply run `make` and with some luck you should have a sigtrace
binary shortly after.


## Usage

sigtrace can attach either to an existing pid or execute a given program.

To execute a given program simply append the program path and its arguments at the end
of the command line. Using `ls` as example this would be `sigtrace /bin/ls -ahl`.
Specifying the complete path is necessary as the PATH variable is not evaluated.
The current environment is provided to the executed process.

Alternatively it is possible to attach to an already running process using the -p
argument. The syntax for this is `sigtrace -p <pid>`. sigtrace will stay attached
until the target process exits or sigtrace itself is closed.

To block signals the -b argument may be used. It accepts a comma separated list of
signal numbers from 1 to 63. The following example would block SIGINT and SIGTERM:
`sigtrace -b 2,15 -p <pid>`.


## Return value

On success 0 is returned. On error a value greater than 0 is returned.


## Limitations

Some signals such as SIGKILL cannot be captured or blocked.

sigtrace relies on process information being available in /proc/<pid>.
If the signal sending process exits too fast this information may not
be available and only its pid is shown. The -a argument can help in
some cases. This will cause sigtrace to attach to the signal sender
in an attempt to stop it before it can exit. In this case it is
recommended to run sigtrace as root.
