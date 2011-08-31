# SSH external for LiveCode

This external uses libssh library (http://www.libssh.org/) to provide SSH functions to LiveCode programs.

## Contents of the package

* livessh/ — this directory contains copy of libssh with compiled binaries.
* binaries/ — this directory contains external builds for Linux (livessh.so) and Windows (livessh.dll). 
* livessh.c — external source code.
* Makefile — build scenario for external.
* demos/ — LiveCode demos

## Usage

To use the external, you’ll need to load its binary (livessh.so for Linux, livessh.dll for Windows) in Livecode. You also need libssh.dll to be either placed in directory where you run LiveCode or to copy it to WINDOWS/System32 on Windows, on Linux you can install libssh using the package manager.

## Compiling

To compile the external on Windows, you need to install MinGW32, then open a command line prompt in livessh directory and run

**make livessh.dll**

To compile the external on Linux, you need to install gcc, make, libssh with development headers, then run

**make livessh.so**

To compile the external on Mac OS X, you need to install libssh (for example, from macports), gcc and make, then run 

**make livessh**

## Developing

The external exports all the functions from libssh, documentation on which you can see on its site: [http://api.libssh.org/stable/](http://api.libssh.org/stable/). Arguments to function calls are translated as follows:

* char * — LiveCode string as is
* int, unsigned int, etc. numbers — read from LiveCode string in according format. 
* Pointers — read from LiveCode string in platform-specific

Exceptions:

* ssh_channel_read: second argument is name of LiveCode variable, which will be used for output 
* ssh_channel_write: second argument is name of LiveCode variable, which will be used for input 
* ssh_channel_read_nonblocking: second argument is name of LiveCode variable, which will be used for output 
* ssh_scp_new: 3+ arguments are interpreted as flags combination; possible values are: “write”, “read”, “recursive” 
* ssh_scp_write: second argument is name of LiveCode variable, which will be used for input
* ssh_scp_read: second argument is name of LiveCode variable, which will be used for output
* sftp_open: third and fourth arguments are swapped, 4+ arguments are interpreted as flags combination; possible values are “readonly”, “writeonly”, “readwrite”, “create”, “excl”, “truncate”.
* sftp_write: last variable is name of LiveCode variable, which will be used for input
* ssh_bind_options_set: second argument is a string. Its possible values:

<table>
	<tr>
		<th>LiveCode string</th>
		<th>Original libssh constant</th>
	</tr>
	<tr>
		<td>addr</td>
		<td>SSH_BIND_OPTIONS_BINDADDR</td>
	</tr>
	<tr>
		<td>log_verbosity</td>
		<td>SSH_BIND_OPTIONS_LOG_VERBOSITY</td>
	</tr>
	<tr>
		<td>port</td>
		<td>SSH_BIND_OPTIONS_BINDPORT_STR</td>
	</tr>
	<tr>
		<td>hostkey</td>
		<td>SSH_BIND_OPTIONS_HOSTKEY</td>
	</tr>
	<tr>
		<td>dsakey</td>
		<td>SSH_BIND_OPTIONS_DSAKEY</td>
	</tr>
	<tr>
		<td>banner</td>
		<td>SSH_BIND_OPTIONS_BANNER</td>
	</tr>
</table>

* ssh_message_auth_set_methods: second argument is interpreted as flags combination; possible values are

<table>
	<tr>
		<td>unknown</td>
		<td>SSH_AUTH_METHOD_UNKNOWN</td>
	</tr>
	<tr>
		<td>password</td>
		<td>SSH_AUTH_METHOD_PASSWORD</td>
	</tr>
	<tr>
		<td>publickey</td>
		<td>SSH_AUTH_METHOD_PUBLICKEY</td>
	</tr>
	<tr>
		<td>hostbased</td>
		<td>SSH_AUTH_METHOD_HOSTBASED</td>
	</tr>
	<tr>
		<td>interactive</td>
		<td>SSH_AUTH_METHOD_INTERACTIVE</td>
	</tr>
</table>

* ssh_ssh_options_set: second argument is a string. Its possible values:

<table>
	<tr>
		<td>host</td>
		<td>SSH_OPTIONS_HOST</td>
	</tr>
	<tr>
		<td>port</td>
		<td>SSH_OPTIONS_PORT_STR</td>
	</tr>
	<tr>
		<td>bindaddr</td>
		<td>SSH_OPTIONS_BINDADDR</td>
	</tr>
	<tr>
		<td>user</td>
		<td>SSH_OPTIONS_USER</td>
	</tr>
	<tr>
		<td>knownhosts</td>
		<td>SSH_OPTIONS_KNOWNHOSTS</td>
	</tr>
	<tr>
		<td>identity</td>
		<td>SSH_OPTIONS_IDENTITY</td>
	</tr>
	<tr>
		<td>timeout</td>
		<td>SSH_OPTIONS_TIMEOUT</td>
	</tr>
	<tr>
		<td>timeout_usec</td>
		<td>SSH_OPTIONS_TIMEOUT_USEC</td>
	</tr>
	<tr>
		<td>ssh1</td>
		<td>SSH_OPTIONS_SSH1</td>
	</tr>
	<tr>
		<td>ssh2</td>
		<td>SSH_OPTIONS_SSH2</td>
	</tr>
	<tr>
		<td>log_verbosity</td>
		<td>SSH_OPTIONS_LOG_VERBOSITY</td>
	</tr>
	<tr>
		<td>ciphers_c_s</td>
		<td>SSH_OPTIONS_CIPHERS_C_S</td>
	</tr>
	<tr>
		<td>ciphers_s_c</td>
		<td>SSH_OPTIONS_CIPHERS_S_C</td>
	</tr>
	<tr>
		<td>compression_c_s</td>
		<td>SSH_OPTIONS_COMPRESSION_C_S</td>
	</tr>
	<tr>
		<td>compression_s_c</td>
		<td>SSH_OPTIONS_COMPRESSION_S_C</td>
	</tr>
	<tr>
		<td>proxycommand</td>
		<td>SSH_OPTIONS_PROXYCOMMAND</td>
	</tr>
</table>

* sftp_read: second argument is a name of LiveCode variable used for output. 
* sftp_async_read: second argument is a name of LiveCode variable used for output.

New function defined:

livessh_run_command(ssh_session, command, outstr)

Runs a given command in shell and stores output in given variable. 

Arguments:
* ssh_session: pointer to ssh session
* command: string with command to run in shell
* outstr: name of variable to use for command output.

Full list of exported functions and commands is available in API.txt

## Demos

Three demos are available in demos/ folder. How to use them: open in LiveCode, input path to SSH external binary in top- most field, press “Load”, input demo-specific data in other fields, press the lowest button. Don’t forget that libssh.dll should be either in current directory or in WINDOWS/System32 on windows for external to work.
