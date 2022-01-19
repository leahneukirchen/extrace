## 0.9 (2022-01-19)

* With `-t`, print time when process execed.
* Fix `-p` flag, which was a regression in 0.8.
* Quit when parent specified in `-p` exits.
* Fix likely root cause for pid_db overflow.

## 0.8 (2021-08-05)

* extrace: add option -Q to suppress runtime errors.
* Small fixes.

## 0.7 (2019-02-08)

* pwait: detect and warn for non-existing PID.
* extract: detect and error for non-existing PID in `-p`.
* Bug fixes.

## 0.6 (2018-06-19)

* Add `-u` to print owner of process.
* Improved /proc/$PID/stat parser.

## 0.5 (2018-03-23)

* Detect and report out of order and lost messages.
* Ensure cmdline is read first.
* Use openat() for speedup.
* Remove custom SIGINT handler.

## 0.4 (2017-08-21)

* Add `-t` for tracing process exit and duration.

## 0.3.1 (2017-04-25)

* Bug fix release

## 0.3 (2016-06-14)

* Add `-e` to output environment
