ipmitool
========

* based on http://sourceforge.net/projects/ipmitool/files/ipmitool/1.8.13/
* to be used with http://github.com/speedops/node-ffi-impi


goals
=====

* make it useful as a library
* make one interface connect session and allow multiple commands to run rather than doing ipmitool command at CLI which will make connect for every such command
* allow arbitrary commands to be run from lib API with easy argv[] api


reasons
=======

* ipmitool seems hard coded to be CLI tool
* internal implementation assumes being a CLI tool and does not allow proper usage as a library
* the sequence of calls to properly run a command and thus proper profile of function calls is not clearly defined


So this is a gross hack to allow controlling this software from external program (written in other languages) via FFI.




