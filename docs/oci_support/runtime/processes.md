# OCI Process Configuration

Status: Initial normative specification

The initial manifest does not contain a `process` object. QOS gets process
defaults from the verified OCI image configuration.

## Arguments

QOS MUST create the argument list from OCI `Entrypoint` followed by OCI `Cmd`.

QOS MUST reject an empty final argument list.

QOS MUST preserve argument boundaries. QOS MUST NOT evaluate the argument list
through a shell unless the image explicitly invokes a shell.

QOS MUST reject an argument that contains a NUL byte.

If the executable argument contains `/`, QOS MUST resolve it as a path inside
the workload root file system.

If the executable argument does not contain `/`, QOS MUST search the
workload's `PATH` in order, like `execvp`. QOS MUST reject the workload when it
cannot find an executable regular file.

## Environment

QOS MUST get environment variables from OCI `Env`.

Each OCI `Env` entry MUST contain `=`. The name before the first `=` MUST be
nonempty and MUST NOT contain NUL. The value after the first `=` MUST NOT
contain NUL.

If the image contains a name more than once, the last entry for that name MUST
win. QOS MUST pass at most one entry for each environment name.

If the image does not define `PATH`, QOS MUST add
`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.

QOS MUST NOT add a QOS key to the environment.

QOS MUST NOT add another environment variable except a fixed non-secret value
defined by the QOS codebase.

## Working directory

QOS MUST get the working directory from OCI `WorkingDir`.

QOS MUST use `/` when the image does not specify a working directory.

The working directory MUST be absolute inside the container.

QOS MUST reject a working directory that escapes the root file system or does
not exist at process start.

## Process user

QOS MUST get the process user from OCI `User`.

OCI `User` can contain:

- a numeric user;
- a user name;
- `user:group`;
- `uid:gid`;
- `uid:group`;
- `user:gid`.

When OCI `User` is empty, QOS MUST use UID 0 and GID 0 with no supplementary
groups.

QOS MUST copy an explicitly numeric user or group as a numeric UID or GID.

QOS MUST resolve a user name or group name from `/etc/passwd` or `/etc/group`
inside the verified root file system.

When a nonempty OCI `User` omits the group, QOS MUST find the matching user
record. QOS MUST use its primary group and supplementary groups from the
verified root file system.

When OCI `User` specifies a group, QOS MUST use that group and MUST NOT add
supplementary groups from the image.

QOS MUST reject a required user or group that it cannot resolve.

QOS MUST give `libcontainer` numeric UID, GID, and supplementary GID values.

Numeric UID and GID text MUST contain only decimal digits and MUST fit the
Linux UID or GID range. QOS MUST reject a negative, overflowing, or malformed
value.

QOS MUST NOT assign a new process UID only to distinguish one workload from
another workload.

The process user is an application setting and a defense-in-depth control. It
is not the workload identity or a security boundary between workloads.

## Standard streams and terminal

The initial runtime MUST set `terminal` to `false`.

Standard input MUST read from `/dev/null`.

QOS MUST collect standard output and standard error as separate workload log
streams associated with the workload name. Log collection MUST use bounded
buffers or bounded streaming so a workload cannot block because QOS stopped
reading a pipe.

Application output is controlled by the trusted workload and can contain
sensitive data. QOS MUST NOT claim that it can redact a key that the workload
chooses to print.

## Umask and limits

The initial process umask MUST be `0022`.

The QOS codebase MAY define fixed process resource limits. The host, image,
and manifest MUST NOT supply OCI runtime resource limits in the initial
feature.

## Stop behavior

QOS MUST use the verified OCI image `StopSignal` when it is present and valid.
Otherwise, QOS MUST use `SIGTERM`.

A valid stop signal is a Linux signal name or positive Linux signal number.
QOS MUST reject an image with a nonempty invalid `StopSignal`.

During node shutdown, QOS MUST send the stop signal to the container process,
wait 10 seconds, and then send `SIGKILL` if the process is still running.

## Future compatibility

A later Manifest V3 specification MAY add command, environment, working
directory, or user overrides.

An absent override MUST preserve the image-derived behavior in this document.

Parent UID and GID mappings are not part of the initial process model. Future
user-namespace behavior is specified in
[User namespaces](../future/user_namespaces.md).
