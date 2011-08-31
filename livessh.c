#include <external.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <libssh/server.h>
#include <stdlib.h> 
#include <stdio.h> 
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>


#define LIVECODE_FUNCTION(x) void x(char *p_arguments[], int p_argument_count, char **r_result, Bool *r_pass, Bool *r_err)
#define LIVECODE_ERROR(x) { *r_err = True; 		*r_pass = False; 		*r_result = strdup(x); 		return; }

#define LIVECODE_READARG(var, number, tmpl) if(!sscanf(p_arguments[ number ], tmpl, & var)) { 	LIVECODE_ERROR("Failed to read argument"); }

#define LIVECODE_ARG(argn) { if(p_argument_count < argn) { 	LIVECODE_ERROR("Incorrect number of arguments"); }}

#define LIVECODE_NOERROR { *r_err = False; *r_pass = False; *r_result = strdup(""); }

#define LIVECODE_RETURN_THIS_STRING(x) { *r_err = False; *r_pass = False; *r_result = x; }

#define LIVECODE_RETURN_POINTER { \
	if(result == NULL) \
		LIVECODE_ERROR("Error.") \
	else \
	{ \
		LIVECODE_NOERROR; \
		*r_result = malloc(20); \
		snprintf(*r_result, 20, "%p", result); \
	} \
}

#define LIVECODE_RETURN_SIGNED { \
	*r_err = False; *r_pass = False; \
	*r_result = malloc(20); \
	snprintf(*r_result, 20, "%d", result); \
}

#define LIVECODE_RETURN_UNSIGNED { \
	*r_err = False; *r_pass = False; \
	*r_result = malloc(20); \
	snprintf(*r_result, 20, "%d", result); \
}

#define LIVECODE_ERR_OK(msg) { \
	if(result == SSH_OK) \
		LIVECODE_NOERROR \
	else \
		LIVECODE_ERROR(msg); \
}

#define LIVECODE_RETURN_STRING { \
	if(result == NULL) \
		LIVECODE_ERROR("Error.") \
	else \
	{ \
		*r_err = False; *r_pass = False; \
		*r_result = result; \
	} \
}

#define LIVECODE_SSH_ERROR { \
	*r_err = True; \
	*r_pass = False; \
	*r_result = ssh_get_error(livessh_session); \
}

// void debug_log(char *fmt, ...)
// {
// 	FILE *fhand = fopen("E:\\log.txt","a");
// 	va_list vl;
// 	va_start(vl, fmt);
// 	vfprintf(fhand, fmt, vl);
// 	va_end(vl);
// 	fclose(fhand);
// }

LIVECODE_FUNCTION(livessh_ssh_channel_accept_x11)
{
	LIVECODE_ARG(2);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int timeout_ms;
	LIVECODE_READARG(timeout_ms, 1, "%d");
	ssh_channel result = ssh_channel_accept_x11(channel, timeout_ms);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_channel_change_pty_size)
{
	LIVECODE_ARG(3);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int cols;
	LIVECODE_READARG(cols, 1, "%d");
	int rows;
	LIVECODE_READARG(rows, 2, "%d");
	int result = ssh_channel_change_pty_size(channel, cols, rows);
	if(result == SSH_OK)
		LIVECODE_NOERROR
	else
		LIVECODE_ERROR("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_close)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int result = ssh_channel_close(channel);
	if(result == SSH_OK)
		LIVECODE_NOERROR
	else
		LIVECODE_ERROR("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_free)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	ssh_channel_free(channel);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_channel_get_exit_status)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int result = ssh_channel_get_exit_status(channel);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_get_session)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	ssh_session result = ssh_channel_get_session(channel);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_channel_is_closed)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int result = ssh_channel_is_closed(channel);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_is_eof)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int result = ssh_channel_is_eof(channel);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_is_open)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int result = ssh_channel_is_open(channel);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_new)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_channel result = ssh_channel_new(session);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_channel_open_forward)
{
	LIVECODE_ARG(5);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	const char * remotehost;
	remotehost = p_arguments[1];
	int remoteport;
	LIVECODE_READARG(remoteport, 2, "%d");
	const char * sourcehost;
	sourcehost = p_arguments[3];
	int localport;
	LIVECODE_READARG(localport, 4, "%d");
	int result = ssh_channel_open_forward(channel, remotehost, remoteport, sourcehost, localport);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_open_session)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int result = ssh_channel_open_session(channel);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_poll)
{
	LIVECODE_ARG(2);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int is_stderr;
	LIVECODE_READARG(is_stderr, 1, "%d");
	int result = ssh_channel_poll(channel, is_stderr);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_read)
{
	LIVECODE_ARG(4);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	char * varname = p_arguments[1];
	uint32_t count;
	LIVECODE_READARG(count, 2, "%u");
	void * dest = malloc(count);
	int is_stderr;
	LIVECODE_READARG(is_stderr, 3, "%d");
	int result = ssh_channel_read(channel, dest, count, is_stderr);
	ExternalString exs; 
	exs.buffer = dest;
	exs.length = result;
	int suc;
	SetVariableEx(varname, strdup(""), &exs, &suc);
	if(suc == EXTERNAL_SUCCESS)
	{
		LIVECODE_RETURN_SIGNED;
	}
	else
	{
		LIVECODE_ERROR("Failed to allocate string");
	} 
}
LIVECODE_FUNCTION(livessh_ssh_channel_read_nonblocking)
{
	LIVECODE_ARG(4);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	uint32_t count;
	LIVECODE_READARG(count, 2, "%u");
	int is_stderr;
	LIVECODE_READARG(is_stderr, 3, "%d");
	
	
	ExternalString exs; 
	exs.buffer=malloc(count);
	int result = ssh_channel_read_nonblocking(channel, exs.buffer, count, is_stderr);
	exs.length = result;
	int suc;
	SetVariableEx(p_arguments[1], strdup(""), &exs, &suc);
	
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_request_env)
{
	LIVECODE_ARG(3);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	const char * name;
	name = p_arguments[1];
	const char * value;
	value = p_arguments[2];
	int result = ssh_channel_request_env(channel, name, value);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_request_exec)
{
	LIVECODE_ARG(2);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	const char * cmd;
	cmd = p_arguments[1];
	int result = ssh_channel_request_exec(channel, cmd);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_request_pty)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int result = ssh_channel_request_pty(channel);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_request_pty_size)
{
	LIVECODE_ARG(4);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	const char * term;
	term = p_arguments[1];
	int cols;
	LIVECODE_READARG(cols, 2, "%d");
	int rows;
	LIVECODE_READARG(rows, 3, "%d");
	int result = ssh_channel_request_pty_size(channel, term, cols, rows);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_request_shell)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int result = ssh_channel_request_shell(channel);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_request_send_signal)
{
	LIVECODE_ARG(2);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	const char * signum;
	signum = p_arguments[1];
	int result = ssh_channel_request_send_signal(channel, signum);
	LIVECODE_ERR_OK("Error");
}

LIVECODE_FUNCTION(livessh_ssh_channel_request_subsystem)
{
	LIVECODE_ARG(2);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	const char * subsystem;
	subsystem = p_arguments[1];
	int result = ssh_channel_request_subsystem(channel, subsystem);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_request_x11)
{
	LIVECODE_ARG(5);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int single_connection;
	LIVECODE_READARG(single_connection, 1, "%d");
	const char * protocol;
	if(strlen(p_arguments[2]) == 0)
		protocol = NULL;
	else
		protocol = p_arguments[2];
	const char * cookie;
	if(strlen(p_arguments[3]) == 0)
		cookie = NULL;
	else
		cookie = p_arguments[3];
	int screen_number;
	LIVECODE_READARG(screen_number, 4, "%d");
	int result = ssh_channel_request_x11(channel, single_connection, protocol, cookie, screen_number);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_channel_send_eof)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int result = ssh_channel_send_eof(channel);
	LIVECODE_ERR_OK("Error");
}

LIVECODE_FUNCTION(livessh_ssh_channel_set_blocking)
{
	LIVECODE_ARG(2);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int blocking;
	LIVECODE_READARG(blocking, 1, "%d");
	ssh_channel_set_blocking(channel, blocking);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_channel_write)
{
	LIVECODE_ARG(2);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	char * varname = p_arguments[1];
	ExternalString exs; 
	int suc;
	GetVariableEx(varname, strdup(""), &exs, &suc);
	if(suc == EXTERNAL_SUCCESS)
	{
		LIVECODE_NOERROR;
	}
	else
	{
		LIVECODE_ERROR("Failed to read string");
	}
	int result = ssh_channel_write(channel, exs.buffer, exs.length);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_window_size)
{
	LIVECODE_ARG(1);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	uint32_t result = ssh_channel_window_size(channel);
	LIVECODE_RETURN_UNSIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_try_publickey_from_file)
{
	LIVECODE_ARG(4);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * keyfile;
	keyfile = p_arguments[1];
	ssh_string * publickey;
	LIVECODE_READARG(publickey, 2, "%p");
	int * type;
	LIVECODE_READARG(type, 3, "%p");
	int result = ssh_try_publickey_from_file(session, keyfile, publickey, type);
	LIVECODE_RETURN_SIGNED;
}

LIVECODE_FUNCTION(livessh_ssh_basename)
{
	LIVECODE_ARG(1);
	const char * path;
	path = p_arguments[0];
	char * result = ssh_basename(path);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_clean_pubkey_hash)
{
	LIVECODE_ARG(1);
	unsigned char ** hash;
	LIVECODE_READARG(hash, 0, "%p");
	ssh_clean_pubkey_hash(hash);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_connect)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_connect(session);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_copyright)
{
	LIVECODE_ARG(0);
	const char * result = ssh_copyright();
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_disconnect)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_disconnect(session);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_dirname)
{
	LIVECODE_ARG(1);
	const char * path;
	path = p_arguments[0];
	char * result = ssh_dirname(path);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_finalize)
{
	LIVECODE_ARG(0);
	int result = ssh_finalize();
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_forward_accept)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int timeout_ms;
	LIVECODE_READARG(timeout_ms, 1, "%d");
	ssh_channel result = ssh_forward_accept(session, timeout_ms);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_forward_cancel)
{
	LIVECODE_ARG(3);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * address;
	address = p_arguments[1];
	int port;
	LIVECODE_READARG(port, 2, "%d");
	int result = ssh_forward_cancel(session, address, port);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_forward_listen)
{
	LIVECODE_ARG(4);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * address;
	address = p_arguments[1];
	int port;
	LIVECODE_READARG(port, 2, "%d");
	int * bound_port;
	LIVECODE_READARG(bound_port, 3, "%p");
	int result = ssh_forward_listen(session, address, port, bound_port);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_free)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_free(session);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_get_disconnect_message)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * result = ssh_get_disconnect_message(session);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_get_error)
{
	LIVECODE_ARG(1);
	void * error;
	LIVECODE_READARG(error, 0, "%p");
	const char * result = ssh_get_error(error);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_get_error_code)
{
	LIVECODE_ARG(1);
	void * error;
	LIVECODE_READARG(error, 0, "%p");
	int result = ssh_get_error_code(error);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_get_fd)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	socket_t result = ssh_get_fd(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_get_hexa)
{
	LIVECODE_ARG(2);
	const unsigned char * what;
	what = p_arguments[0];
	size_t len;
	LIVECODE_READARG(len, 1, "%u");
	char * result = ssh_get_hexa(what, len);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_get_issue_banner)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	char * result = ssh_get_issue_banner(session);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_get_openssh_version)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_get_openssh_version(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_get_pubkey)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_string result = ssh_get_pubkey(session);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_get_pubkey_hash)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	unsigned char ** hash;
	LIVECODE_READARG(hash, 1, "%p");
	int result = ssh_get_pubkey_hash(session, hash);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_get_random)
{
	LIVECODE_ARG(3);
	void * where;
	LIVECODE_READARG(where, 0, "%p");
	int len;
	LIVECODE_READARG(len, 1, "%d");
	int strong;
	LIVECODE_READARG(strong, 2, "%d");
	int result = ssh_get_random(where, len, strong);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_get_version)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_get_version(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_get_status)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_get_status(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_init)
{
	LIVECODE_ARG(0);
	int result = ssh_init();
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_is_blocking)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_is_blocking(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_is_connected)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_is_connected(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_is_server_known)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_is_server_known(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_open_reply_accept)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	ssh_channel result = ssh_message_channel_request_open_reply_accept(msg);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_reply_success)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_channel_request_reply_success(msg);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_message_free)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	ssh_message_free(msg);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_message_get)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_message result = ssh_message_get(session);
	if(result == NULL)
	{
		LIVECODE_NOERROR;
		*r_result = strdup("0x0");
	}
	else 
	{
		LIVECODE_NOERROR;
		*r_result = malloc(20);
		snprintf(*r_result, 20, "%p", result);
	}
}
LIVECODE_FUNCTION(livessh_ssh_message_subtype)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_subtype(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_type)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_type(msg);
	switch(result)
	{
		case SSH_REQUEST_AUTH:
			LIVECODE_RETURN_THIS_STRING(strdup("request_auth"));
			break;
		case SSH_REQUEST_CHANNEL_OPEN:
			LIVECODE_RETURN_THIS_STRING(strdup("request_channel_open"));
			break;
		case SSH_REQUEST_CHANNEL:
			LIVECODE_RETURN_THIS_STRING(strdup("request_channel"));
			break;
		case SSH_REQUEST_SERVICE:
			LIVECODE_RETURN_THIS_STRING(strdup("request_service"));
			break;
		case SSH_REQUEST_GLOBAL:
			LIVECODE_RETURN_THIS_STRING(strdup("request_global"));
			break;
		default:
			LIVECODE_RETURN_THIS_STRING(strdup("unmatched"));
	}
	
}
LIVECODE_FUNCTION(livessh_ssh_mkdir)
{
	LIVECODE_ARG(2);
	const char * pathname;
	pathname = p_arguments[0];
	mode_t mode;
	unsigned int modeo; LIVECODE_READARG(modeo, 1, "%o"); mode = modeo;
	int result = ssh_mkdir(pathname, mode);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_new)
{
	LIVECODE_ARG(0);
	ssh_session result = ssh_new();
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_options_copy)
{
	LIVECODE_ARG(2);
	ssh_session src;
	LIVECODE_READARG(src, 0, "%p");
	ssh_session * dest;
	LIVECODE_READARG(dest, 1, "%p");
	int result = ssh_options_copy(src, dest);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_options_getopt)
{
	LIVECODE_ARG(3);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int * argcptr;
	LIVECODE_READARG(argcptr, 1, "%p");
	char ** argv;
	LIVECODE_READARG(argv, 2, "%p");
	int result = ssh_options_getopt(session, argcptr, argv);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_options_parse_config)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * filename;
	filename = p_arguments[1];
	int result = ssh_options_parse_config(session, filename);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_options_set)
{
	if(p_argument_count < 3)
	{
		LIVECODE_ERROR("Incorrect number of arguments");
	}
	ssh_session livessh_session;
	if(!sscanf(p_arguments[0], "%p", &livessh_session))
	{
		LIVECODE_ERROR("Failed to read argument");
	}
	*r_err = True;
	*r_pass = False;
	if(!strcmp(p_arguments[1], "host"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_HOST, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "port"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_PORT_STR, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "bindaddr"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_BINDADDR, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "user"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_USER, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "knownhosts"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_KNOWNHOSTS, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "identity"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_IDENTITY, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "timeout"))
	{
		long l_time;
		if(sscanf(p_arguments[2], "%d", &l_time))
		{
			ssh_options_set(livessh_session, SSH_OPTIONS_TIMEOUT, (void*)(&l_time));
			*r_err = False;
		} else
		{
			LIVECODE_ERROR("Couldn't read time");
		}
	}
	if(!strcmp(p_arguments[1], "timeout_usec"))
	{
		long l_time;
		if(sscanf(p_arguments[2], "%d", &l_time))
		{
			ssh_options_set(livessh_session, SSH_OPTIONS_TIMEOUT_USEC, (void *)(&l_time));
			*r_err = False;
		} else
		{
			LIVECODE_ERROR("Couldn't read time");
		}
	}
	if(!strcmp(p_arguments[1], "ssh1"))
	{
		int b_ssh1;
		if(sscanf(p_arguments[2], "%d", &b_ssh1))
		{
			ssh_options_set(livessh_session, SSH_OPTIONS_SSH1, (void*)(&b_ssh1));
			*r_err = False;
		} else
		{
			LIVECODE_ERROR("Couldn't read int");
		}
	}
	if(!strcmp(p_arguments[1], "ssh2"))
	{
		int b_ssh2;
		if(sscanf(p_arguments[2], "%d", &b_ssh2))
		{
			ssh_options_set(livessh_session, SSH_OPTIONS_SSH2, (void*)(&b_ssh2));
			*r_err = False;
		} else
		{
			LIVECODE_ERROR("Couldn't read int");
		}
	}
	if(!strcmp(p_arguments[1], "log_verbosity"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_LOG_VERBOSITY_STR, p_arguments[2]);
		*r_err = False;
	}
	// TODO: callbacks?
	if(!strcmp(p_arguments[1], "ciphers_c_s"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_CIPHERS_C_S, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "ciphers_s_c"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_CIPHERS_S_C, p_arguments[2]);
		*r_err = False;
	}
	// TODO: newer version?
// 	if(!strcmp(p_arguments[1], "key_exchange"))
// 	{
// 		ssh_options_set(livessh_session, SSH_OPTIONS_KEY_EXCHANGE, p_arguments[2]);
// 		*r_err = False;
// 	}
	if(!strcmp(p_arguments[1], "compression_c_s"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_COMPRESSION_C_S, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "compression_s_c"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_COMPRESSION_S_C, p_arguments[2]);
		*r_err = False;
	}
// 	if(!strcmp(p_arguments[1], "compression"))
// 	{
// 		ssh_options_set(livessh_session, SSH_OPTIONS_COMPRESSION, p_arguments[2]);
// 		*r_err = False;
// 	}
// 	if(!strcmp(p_arguments[1], "compression_level"))
// 	{
// 		int i_comp;
// 		if(sscanf(p_arguments[2], "%d", &i_comp))
// 		{
// 			ssh_options_set(livessh_session, SSH_OPTIONS_COMPRESSION_LEVEL, (void*)(&i_comp));
// 			*r_err = False;
// 		} else
// 		{
// 			LIVECODE_ERROR("Couldn't read int");
// 		}
// 	}
// 	if(!strcmp(p_arguments[1], "stricthostkeycheck"))
// 	{
// 		int b_strict;
// 		if(sscanf(p_arguments[2], "%d", &b_strict))
// 		{
// 			ssh_options_set(livessh_session, SSH_OPTIONS_STRICTHOSTKEYCHECK, (void*)(&b_strict));
// 			*r_err = False;
// 		} else
// 		{
// 			LIVECODE_ERROR("Couldn't read int");
// 		}
// 	}
	if(!strcmp(p_arguments[1], "proxycommand"))
	{
		ssh_options_set(livessh_session, SSH_OPTIONS_PROXYCOMMAND, p_arguments[2]);
		*r_err = False;
	}
	if(*r_err == True)
	{
		LIVECODE_ERROR("No such option");
	} else
		*r_result=strdup("");
}
LIVECODE_FUNCTION(livessh_ssh_pcap_file_close)
{
	LIVECODE_ARG(1);
	ssh_pcap_file pcap;
	LIVECODE_READARG(pcap, 0, "%p");
	int result = ssh_pcap_file_close(pcap);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_pcap_file_free)
{
	LIVECODE_ARG(1);
	ssh_pcap_file pcap;
	LIVECODE_READARG(pcap, 0, "%p");
	ssh_pcap_file_free(pcap);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_pcap_file_new)
{
	LIVECODE_ARG(0);
	ssh_pcap_file result = ssh_pcap_file_new();
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_pcap_file_open)
{
	LIVECODE_ARG(2);
	ssh_pcap_file pcap;
	LIVECODE_READARG(pcap, 0, "%p");
	const char * filename;
	filename = p_arguments[1];
	int result = ssh_pcap_file_open(pcap, filename);
	LIVECODE_RETURN_SIGNED;
}
// LIVECODE_FUNCTION(livessh_ssh_privatekey_type)
// {
// 	LIVECODE_ARG(1);
// 	ssh_private_key privatekey;
// 	LIVECODE_READARG(privatekey, 0, "%p");
// 	enum ssh_keytypes_e result = ssh_privatekey_type(privatekey);
// 	switch(result)
// 	{
// 		SSH_KEYTYPE_RSA: *r_result = strdup("RSA"); break;
// 		SSH_KEYTYPE_DSS: *r_result = strdup("DSS"); break;
// 		SSH_KEYTYPE_RSA1: *r_result = strdup("RSA1"); break;
// 		SSH_KEYTYPE_UNKNOWN: *r_result = strdup("UNKNOWN"); break;
// 	}
// }
LIVECODE_FUNCTION(livessh_ssh_print_hexa)
{
	LIVECODE_ARG(3);
	const char * descr;
	descr = p_arguments[0];
	const unsigned char * what;
	what = p_arguments[1];
	size_t len;
	LIVECODE_READARG(len, 2, "%u");
	ssh_print_hexa(descr, what, len);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_scp_accept_request)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	int result = ssh_scp_accept_request(scp);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_scp_close)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	int result = ssh_scp_close(scp);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_scp_deny_request)
{
	LIVECODE_ARG(2);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	const char * reason;
	reason = p_arguments[1];
	int result = ssh_scp_deny_request(scp, reason);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_scp_free)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	ssh_scp_free(scp);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_scp_init)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	int result = ssh_scp_init(scp);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_scp_leave_directory)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	int result = ssh_scp_leave_directory(scp);
	LIVECODE_RETURN_SIGNED;
}

LIVECODE_FUNCTION(livessh_ssh_scp_new)
{
	LIVECODE_ARG(3);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int i;
	int mode = 0;
	for(i = 2; i < p_argument_count; ++i)
	{
		if(!strcmp(p_arguments[i], "write"))
			mode = SSH_SCP_WRITE;
		if(!strcmp(p_arguments[i], "read"))
			mode = SSH_SCP_READ;
		if(!strcmp(p_arguments[i], "recursive"))
			mode = mode | SSH_SCP_RECURSIVE;
	}
	const char * location;
	location = p_arguments[2];
	ssh_scp result = ssh_scp_new(session, mode, location);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_scp_pull_request)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	int result = ssh_scp_pull_request(scp);
	switch(result)
	{
		case SSH_SCP_REQUEST_NEWFILE:
			LIVECODE_NOERROR;
			*r_result = strdup("NEWFILE");
		break;
		case SSH_SCP_REQUEST_NEWDIR:
			LIVECODE_NOERROR;
			*r_result = strdup("NEWDIRECTORY");
		break;
		case SSH_SCP_REQUEST_ENDDIR:
			LIVECODE_NOERROR;
			*r_result = strdup("END_DIRECTORY");
		break;
	}
}
LIVECODE_FUNCTION(livessh_ssh_scp_push_directory)
{
	LIVECODE_ARG(3);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	const char * dirname;
	dirname = p_arguments[1];
	int mode;
	unsigned int modeo; LIVECODE_READARG(modeo, 2, "%o"); mode = modeo;
	int result = ssh_scp_push_directory(scp, dirname, mode);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_scp_push_file)
{
	LIVECODE_ARG(4);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	const char * filename;
	filename = p_arguments[1];
	size_t size;
	LIVECODE_READARG(size, 2, "%u");
	unsigned int perms;
	LIVECODE_READARG(perms, 3, "%o");
	int result = ssh_scp_push_file(scp, filename, size, perms);
	LIVECODE_ERR_OK("Error");
}

LIVECODE_FUNCTION(livessh_sftp_read)
{
	LIVECODE_ARG(3);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	ExternalString exs;
	int suc;
	size_t count;
	char * varname = p_arguments[1];
	LIVECODE_READARG(count, 2, "%u");
	exs.buffer = malloc(count);
	int result = sftp_read(file, (void*)exs.buffer, count);
	exs.length = result;
	SetVariableEx(varname, strdup(""), &exs, &suc);
	LIVECODE_RETURN_UNSIGNED;
}

LIVECODE_FUNCTION(livessh_ssh_scp_read)
{
	LIVECODE_ARG(3);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	ExternalString exs;
	int suc;
	size_t count;
	char * varname = p_arguments[1];
	LIVECODE_READARG(count, 2, "%u");
	exs.buffer = malloc(count);
	int result = ssh_scp_read(scp, exs.buffer, count);
	exs.length = result;
	SetVariableEx(varname, strdup(""), &exs, &suc);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_scp_request_get_filename)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	const char * result = ssh_scp_request_get_filename(scp);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_scp_request_get_permissions)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	int result = ssh_scp_request_get_permissions(scp);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_scp_request_get_size)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	size_t result = ssh_scp_request_get_size(scp);
	LIVECODE_RETURN_UNSIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_scp_request_get_warning)
{
	LIVECODE_ARG(1);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	const char * result = ssh_scp_request_get_warning(scp);
	LIVECODE_RETURN_STRING;
}

LIVECODE_FUNCTION(livessh_ssh_scp_write)
{
	LIVECODE_ARG(3);
	ssh_scp scp;
	LIVECODE_READARG(scp, 0, "%p");
	char *varname = p_arguments[1];
	ExternalString exs;
	int suc;
	GetVariableEx(varname, 0, &exs, &suc);
	const void * buffer = exs.buffer;
	size_t len = exs.length;
	int result = ssh_scp_write(scp, buffer, len);
	LIVECODE_RETURN_SIGNED;
}

LIVECODE_FUNCTION(livessh_ssh_service_request)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * service;
	service = p_arguments[1];
	int result = ssh_service_request(session, service);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_set_blocking)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int blocking;
	LIVECODE_READARG(blocking, 1, "%d");
	ssh_set_blocking(session, blocking);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_set_fd_except)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_set_fd_except(session);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_set_fd_toread)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_set_fd_toread(session);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_set_fd_towrite)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_set_fd_towrite(session);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_silent_disconnect)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_silent_disconnect(session);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_set_pcap_file)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_pcap_file pcapfile;
	LIVECODE_READARG(pcapfile, 1, "%p");
	int result = ssh_set_pcap_file(session, pcapfile);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_autopubkey)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * passphrase;
	passphrase = p_arguments[1];
	int result = ssh_userauth_autopubkey(session, passphrase);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_kbdint)
{
	LIVECODE_ARG(3);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * user;
	user = p_arguments[1];
	const char * submethods;
	submethods = p_arguments[2];
	int result = ssh_userauth_kbdint(session, user, submethods);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_kbdint_getinstruction)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * result = ssh_userauth_kbdint_getinstruction(session);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_kbdint_getname)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * result = ssh_userauth_kbdint_getname(session);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_kbdint_getnprompts)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_userauth_kbdint_getnprompts(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_kbdint_getprompt)
{
	LIVECODE_ARG(3);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	unsigned int i;
	LIVECODE_READARG(i, 1, "%u");
	char * echo;
	echo = p_arguments[2];
	const char * result = ssh_userauth_kbdint_getprompt(session, i, echo);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_kbdint_setanswer)
{
	LIVECODE_ARG(3);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	unsigned int i;
	LIVECODE_READARG(i, 1, "%u");
	const char * answer;
	answer = p_arguments[2];
	int result = ssh_userauth_kbdint_setanswer(session, i, answer);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_list)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * username;
	username = p_arguments[1];
	int result = ssh_userauth_list(session, username);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_none)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * username;
	username = p_arguments[1];
	int result = ssh_userauth_none(session, username);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_offer_pubkey)
{
	LIVECODE_ARG(4);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * username;
	username = p_arguments[1];
	int type;
	LIVECODE_READARG(type, 2, "%d");
	ssh_string publickey;
	LIVECODE_READARG(publickey, 3, "%p");
	int result = ssh_userauth_offer_pubkey(session, username, type, publickey);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_password)
{
	LIVECODE_ARG(3);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * username;
	username = p_arguments[1];
	const char * password;
	password = p_arguments[2];
	int result = ssh_userauth_password(session, username, password);
	switch(result)
	{
		case SSH_AUTH_ERROR: LIVECODE_ERROR("Serious error"); break;
		case SSH_AUTH_DENIED: LIVECODE_ERROR("Authentication failed"); break;
		case SSH_AUTH_PARTIAL: LIVECODE_RETURN_THIS_STRING(strdup("Partially autheticated")); break;
		case SSH_AUTH_SUCCESS: LIVECODE_RETURN_THIS_STRING(strdup("OK")); break;
		case SSH_AUTH_AGAIN: LIVECODE_RETURN_THIS_STRING(strdup("Again")); break;
	}
}
LIVECODE_FUNCTION(livessh_ssh_userauth_pubkey)
{
	LIVECODE_ARG(4);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * username;
	username = p_arguments[1];
	ssh_string publickey;
	LIVECODE_READARG(publickey, 2, "%p");
	ssh_private_key privatekey;
	LIVECODE_READARG(privatekey, 3, "%p");
	int result = ssh_userauth_pubkey(session, username, publickey, privatekey);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_userauth_privatekey_file)
{
	LIVECODE_ARG(4);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * username;
	username = p_arguments[1];
	const char * filename;
	filename = p_arguments[2];
	const char * passphrase;
	passphrase = p_arguments[3];
	int result = ssh_userauth_privatekey_file(session, username, filename, passphrase);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_version)
{
	LIVECODE_ARG(1);
	int req_version;
	LIVECODE_READARG(req_version, 0, "%d");
	const char * result = ssh_version(req_version);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_write_knownhost)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_write_knownhost(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_string_burn)
{
	LIVECODE_ARG(1);
	ssh_string str;
	LIVECODE_READARG(str, 0, "%p");
	ssh_string_burn(str);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_string_copy)
{
	LIVECODE_ARG(1);
	ssh_string str;
	LIVECODE_READARG(str, 0, "%p");
	ssh_string result = ssh_string_copy(str);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_string_data)
{
	LIVECODE_ARG(1);
	ssh_string str;
	LIVECODE_READARG(str, 0, "%p");
	void * result = ssh_string_data(str);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_string_fill)
{
	LIVECODE_ARG(3);
	ssh_string str;
	LIVECODE_READARG(str, 0, "%p");
	const void * data;
	LIVECODE_READARG(data, 1, "%p");
	size_t len;
	LIVECODE_READARG(len, 2, "%u");
	int result = ssh_string_fill(str, data, len);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_string_free)
{
	LIVECODE_ARG(1);
	ssh_string str;
	LIVECODE_READARG(str, 0, "%p");
	ssh_string_free(str);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_string_from_char)
{
	LIVECODE_ARG(1);
	const char * what;
	what = p_arguments[0];
	ssh_string result = ssh_string_from_char(what);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_string_len)
{
	LIVECODE_ARG(1);
	ssh_string str;
	LIVECODE_READARG(str, 0, "%p");
	size_t result = ssh_string_len(str);
	LIVECODE_RETURN_UNSIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_string_new)
{
	LIVECODE_ARG(1);
	size_t size;
	LIVECODE_READARG(size, 0, "%u");
	ssh_string result = ssh_string_new(size);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_string_to_char)
{
	LIVECODE_ARG(1);
	ssh_string str;
	LIVECODE_READARG(str, 0, "%p");
	char * result = ssh_string_to_char(str);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_string_free_char)
{
	LIVECODE_ARG(1);
	char * s;
	s = p_arguments[0];
	ssh_string_free_char(s);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_ssh_getpass)
{
	LIVECODE_ARG(5);
	const char * prompt;
	prompt = p_arguments[0];
	char * buf;
	buf = p_arguments[1];
	size_t len;
	LIVECODE_READARG(len, 2, "%u");
	int echo;
	LIVECODE_READARG(echo, 3, "%d");
	int verify;
	LIVECODE_READARG(verify, 4, "%d");
	int result = ssh_getpass(prompt, buf, len, echo, verify);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_new)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	sftp_session result = sftp_new(session);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_free)
{
	LIVECODE_ARG(1);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	sftp_free(sftp);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_sftp_init)
{
	LIVECODE_ARG(1);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	int result = sftp_init(sftp);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_get_error)
{
	LIVECODE_ARG(1);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	int result = sftp_get_error(sftp);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_extensions_get_count)
{
	LIVECODE_ARG(1);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	unsigned int result = sftp_extensions_get_count(sftp);
	LIVECODE_RETURN_UNSIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_extensions_get_name)
{
	LIVECODE_ARG(2);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	unsigned int indexn;
	LIVECODE_READARG(indexn, 1, "%u");
	const char * result = sftp_extensions_get_name(sftp, indexn);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_sftp_extensions_get_data)
{
	LIVECODE_ARG(2);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	unsigned int indexn;
	LIVECODE_READARG(indexn, 1, "%u");
	const char * result = sftp_extensions_get_data(sftp, indexn);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_sftp_extension_supported)
{
	LIVECODE_ARG(3);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * name;
	name = p_arguments[1];
	const char * data;
	data = p_arguments[2];
	int result = sftp_extension_supported(sftp, name, data);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_opendir)
{
	LIVECODE_ARG(2);
	sftp_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * path;
	path = p_arguments[1];
	sftp_dir result = sftp_opendir(session, path);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_readdir)
{
	LIVECODE_ARG(2);
	sftp_session session;
	LIVECODE_READARG(session, 0, "%p");
	sftp_dir dir;
	LIVECODE_READARG(dir, 1, "%p");
	sftp_attributes result = sftp_readdir(session, dir);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_dir_eof)
{
	LIVECODE_ARG(1);
	sftp_dir dir;
	LIVECODE_READARG(dir, 0, "%p");
	int result = sftp_dir_eof(dir);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_stat)
{
	LIVECODE_ARG(2);
	sftp_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * path;
	path = p_arguments[1];
	sftp_attributes result = sftp_stat(session, path);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_lstat)
{
	LIVECODE_ARG(2);
	sftp_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * path;
	path = p_arguments[1];
	sftp_attributes result = sftp_lstat(session, path);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_fstat)
{
	LIVECODE_ARG(1);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	sftp_attributes result = sftp_fstat(file);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_attributes_free)
{
	LIVECODE_ARG(1);
	sftp_attributes file;
	LIVECODE_READARG(file, 0, "%p");
	sftp_attributes_free(file);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_sftp_closedir)
{
	LIVECODE_ARG(1);
	sftp_dir dir;
	LIVECODE_READARG(dir, 0, "%p");
	int result = sftp_closedir(dir);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_close)
{
	LIVECODE_ARG(1);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	int result = sftp_close(file);
	LIVECODE_ERR_OK("Error");
}

LIVECODE_FUNCTION(livessh_sftp_open)
{
	LIVECODE_ARG(4);
	sftp_session session;
	LIVECODE_READARG(session, 0, "%p");
	const char * file;
	file = p_arguments[1];
	int amode = 0;
	int i;
	for(i = 3; i < p_argument_count; ++i)
	{
		if(!strcmp(p_arguments[i], "readonly"))
			amode = O_RDONLY;
		if(!strcmp(p_arguments[i], "writeonly"))
			amode = O_WRONLY;
		if(!strcmp(p_arguments[i], "readwrite"))
			amode = O_RDWR;
		if(!strcmp(p_arguments[i], "create"))
			amode = amode | O_CREAT;
		if(!strcmp(p_arguments[i], "excl"))
			amode = amode | O_EXCL;
		if(!strcmp(p_arguments[i], "truncate"))
			amode = amode | O_TRUNC;
			
	}
	mode_t mode;
	unsigned int modeo; LIVECODE_READARG(modeo, 2, "%o"); mode = modeo;
	sftp_file result = sftp_open(session, file, mode, amode);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_file_set_nonblocking)
{
	LIVECODE_ARG(1);
	sftp_file handle;
	LIVECODE_READARG(handle, 0, "%p");
	sftp_file_set_nonblocking(handle);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_sftp_file_set_blocking)
{
	LIVECODE_ARG(1);
	sftp_file handle;
	LIVECODE_READARG(handle, 0, "%p");
	sftp_file_set_blocking(handle);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_sftp_async_read_begin)
{
	LIVECODE_ARG(2);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	uint32_t len;
	LIVECODE_READARG(len, 1, "%u");
	int result = sftp_async_read_begin(file, len);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_async_read)
{
	LIVECODE_ARG(4);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	char * varname = p_arguments[1];
	uint32_t len;
	LIVECODE_READARG(len, 2, "%u");
	uint32_t id;
	LIVECODE_READARG(id, 3, "%u");
	ExternalString exs;
	exs.buffer = malloc(len);
	int result = sftp_async_read(file, (void *)exs.buffer, len, id);
	exs.length = result;
	int suc;
	SetVariableEx(varname, strdup(""), &exs, &suc);
	LIVECODE_RETURN_SIGNED;
}

LIVECODE_FUNCTION(livessh_sftp_write)
{
	LIVECODE_ARG(2);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	char *varname = p_arguments[1];
	ExternalString exs;
	int suc;
	GetVariableEx(varname,0, &exs, &suc);
	const void * buf = exs.buffer;
	size_t count = exs.length;
	ssize_t result = sftp_write(file, buf, count);
	LIVECODE_RETURN_UNSIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_seek)
{
	LIVECODE_ARG(2);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	uint32_t new_offset;
	LIVECODE_READARG(new_offset, 1, "%u");
	int result = sftp_seek(file, new_offset);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_seek64)
{
	LIVECODE_ARG(2);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	uint64_t new_offset;
	LIVECODE_READARG(new_offset, 1, "%p");
	int result = sftp_seek64(file, new_offset);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_tell)
{
	LIVECODE_ARG(1);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	unsigned long result = sftp_tell(file);
	LIVECODE_RETURN_UNSIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_tell64)
{
	LIVECODE_ARG(1);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	uint64_t result = sftp_tell64(file);
	LIVECODE_RETURN_UNSIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_rewind)
{
	LIVECODE_ARG(1);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	sftp_rewind(file);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_sftp_unlink)
{
	LIVECODE_ARG(2);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * file;
	file = p_arguments[1];
	int result = sftp_unlink(sftp, file);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_rmdir)
{
	LIVECODE_ARG(2);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * directory;
	directory = p_arguments[1];
	int result = sftp_rmdir(sftp, directory);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_mkdir)
{
	LIVECODE_ARG(3);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * directory;
	directory = p_arguments[1];
	mode_t mode;
	unsigned int modeo; LIVECODE_READARG(modeo, 2, "%o"); mode = modeo;
	int result = sftp_mkdir(sftp, directory, mode);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_rename)
{
	LIVECODE_ARG(3);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * original;
	original = p_arguments[1];
	const  char * newname;
	LIVECODE_READARG(newname, 2, "%p");
	int result = sftp_rename(sftp, original, newname);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_setstat)
{
	LIVECODE_ARG(3);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * file;
	file = p_arguments[1];
	sftp_attributes attr;
	LIVECODE_READARG(attr, 2, "%p");
	int result = sftp_setstat(sftp, file, attr);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_chown)
{
	LIVECODE_ARG(4);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * file;
	file = p_arguments[1];
	uid_t owner;
	LIVECODE_READARG(owner, 2, "%p");
	gid_t group;
	LIVECODE_READARG(group, 3, "%p");
	int result = sftp_chown(sftp, file, owner, group);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_chmod)
{
	LIVECODE_ARG(3);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * file;
	file = p_arguments[1];
	mode_t mode;
	unsigned int modeo; LIVECODE_READARG(modeo, 2, "%o"); mode = modeo;
	int result = sftp_chmod(sftp, file, mode);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_utimes)
{
	LIVECODE_ARG(3);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * file;
	file = p_arguments[1];
	const struct timeval * times;
	LIVECODE_READARG(times, 2, "%p");
	int result = sftp_utimes(sftp, file, times);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_symlink)
{
	LIVECODE_ARG(3);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * target;
	target = p_arguments[1];
	const char * dest;
	dest = p_arguments[2];
	int result = sftp_symlink(sftp, target, dest);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_readlink)
{
	LIVECODE_ARG(2);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * path;
	path = p_arguments[1];
	char * result = sftp_readlink(sftp, path);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_sftp_statvfs)
{
	LIVECODE_ARG(2);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * path;
	path = p_arguments[1];
	sftp_statvfs_t result = sftp_statvfs(sftp, path);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_fstatvfs)
{
	LIVECODE_ARG(1);
	sftp_file file;
	LIVECODE_READARG(file, 0, "%p");
	sftp_statvfs_t result = sftp_fstatvfs(file);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_statvfs_free)
{
	LIVECODE_ARG(1);
	sftp_statvfs_t statvfs_o;
	LIVECODE_READARG(statvfs_o, 0, "%p");
	sftp_statvfs_free(statvfs_o);
	LIVECODE_NOERROR;
}
LIVECODE_FUNCTION(livessh_sftp_canonicalize_path)
{
	LIVECODE_ARG(2);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	const char * path;
	path = p_arguments[1];
	char * result = sftp_canonicalize_path(sftp, path);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_sftp_server_version)
{
	LIVECODE_ARG(1);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	int result = sftp_server_version(sftp);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_sftp_server_new)
{
	LIVECODE_ARG(2);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	ssh_channel chan;
	LIVECODE_READARG(chan, 1, "%p");
	sftp_session result = sftp_server_new(session, chan);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_sftp_server_init)
{
	LIVECODE_ARG(1);
	sftp_session sftp;
	LIVECODE_READARG(sftp, 0, "%p");
	int result = sftp_server_init(sftp);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_run_command)
{
	if(p_argument_count < 3)
	{
		LIVECODE_ERROR("Incorrect number of arguments");
	}
	ssh_session session;
	if(!sscanf(p_arguments[0], "%p", &session))
	{
		LIVECODE_ERROR("Failed to read argument 1");
	}
	char *command = p_arguments[1];
	char *outstr = p_arguments[2];
	ssh_channel channel;
	int rc;
	
	channel = ssh_channel_new(session);
	if(channel == NULL)
	{
		*r_err = True;
		*r_pass = False;
		*r_result = strdup("Couldn't create channel");
		return;
	}
	
	rc = ssh_channel_open_session(channel);
	if(rc != SSH_OK)
	{
		ssh_channel_free(channel);
		*r_err = True;
		*r_pass = False;
		*r_result = ssh_get_error(channel);
		return;
	}
	
	rc = ssh_channel_request_exec(channel, command);
	if(rc != SSH_OK)
	{
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		*r_err = True;
		*r_pass = False;
		*r_result = strdup("Couldn't execute command");
		return;
	}
	
	char *out_buffer = 0;
	unsigned int out_counter = 0;
	char buffer[256];
	unsigned int nbytes;
	
	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);

	while (nbytes > 0)
	{
		if(out_buffer == 0)
		{
			out_buffer = malloc(nbytes);
		} else
		{
			char *new_out_buffer = realloc(out_buffer, out_counter + nbytes);
			if(new_out_buffer != NULL)
				out_buffer = new_out_buffer;
			else
			{
				LIVECODE_ERROR("Failed to realloc");
			}
		}
		memcpy(out_buffer + out_counter, buffer, nbytes);
		out_counter += nbytes;
		nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	}
	
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	
	if (nbytes < 0)
	{
		LIVECODE_ERROR("Short read");
	}
	
 	ExternalString exs;
 	exs.buffer = out_buffer;
 	exs.length = out_counter;

	
	SetVariableEx(outstr, NULL, &exs, &rc);
	
	*r_err = False;
	*r_pass = False;
	*r_result = strdup("Success");
	return;
}

LIVECODE_FUNCTION(livessh_ssh_bind_new)
{
	LIVECODE_ARG(0);
	ssh_bind result = ssh_bind_new();
	LIVECODE_RETURN_POINTER;
}

LIVECODE_FUNCTION(livessh_ssh_bind_options_set)
{
	LIVECODE_ARG(3);
	ssh_bind sshbind;
	LIVECODE_READARG(sshbind, 0, "%p");
	*r_err = True;
	*r_pass = False;
	if(!strcmp(p_arguments[1], "addr"))
	{
		ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "port"))
	{
		ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "hostkey"))
	{
		ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "dsakey"))
	{
		ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "rsakey"))
	{
		ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "banner"))
	{
		ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, p_arguments[2]);
		*r_err = False;
	}
	if(!strcmp(p_arguments[1], "log_verbosity"))
	{
		int level;
		if(!sscanf(p_arguments[2], "%d", &level))
			LIVECODE_ERROR("Failed to read int");
		ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, p_arguments[2]);
		*r_err = False;
	}
	if(*r_err == True)
	{
		LIVECODE_ERROR("No such option");
	} else
		*r_result=strdup("");
}
LIVECODE_FUNCTION(livessh_ssh_bind_listen)
{
	LIVECODE_ARG(1);
	ssh_bind ssh_bind_o;
	LIVECODE_READARG(ssh_bind_o, 0, "%p");
	int result = ssh_bind_listen(ssh_bind_o);
	LIVECODE_ERR_OK(ssh_get_error(ssh_bind_o));
}
LIVECODE_FUNCTION(livessh_ssh_bind_set_callbacks)
{
	LIVECODE_ARG(3);
	ssh_bind sshbind;
	LIVECODE_READARG(sshbind, 0, "%p");
	ssh_bind_callbacks callbacks;
	LIVECODE_READARG(callbacks, 1, "%p");
	void * userdata;
	LIVECODE_READARG(userdata, 2, "%p");
	int result = ssh_bind_set_callbacks(sshbind, callbacks, userdata);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_bind_set_blocking)
{
	LIVECODE_ARG(2);
	ssh_bind ssh_bind_o;
	LIVECODE_READARG(ssh_bind_o, 0, "%p");
	int blocking;
	LIVECODE_READARG(blocking, 1, "%d");
	ssh_bind_set_blocking(ssh_bind_o, blocking);
}
LIVECODE_FUNCTION(livessh_ssh_bind_get_fd)
{
	LIVECODE_ARG(1);
	ssh_bind ssh_bind_o;
	LIVECODE_READARG(ssh_bind_o, 0, "%p");
	socket_t result = ssh_bind_get_fd(ssh_bind_o);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_bind_set_fd)
{
	LIVECODE_ARG(2);
	ssh_bind ssh_bind_o;
	LIVECODE_READARG(ssh_bind_o, 0, "%p");
	socket_t fd;
	LIVECODE_READARG(fd, 1, "%p");
	ssh_bind_set_fd(ssh_bind_o, fd);
}
LIVECODE_FUNCTION(livessh_ssh_bind_fd_toaccept)
{
	LIVECODE_ARG(1);
	ssh_bind ssh_bind_o;
	LIVECODE_READARG(ssh_bind_o, 0, "%p");
	ssh_bind_fd_toaccept(ssh_bind_o);
}
LIVECODE_FUNCTION(livessh_ssh_bind_accept)
{
	LIVECODE_ARG(2);
	ssh_bind ssh_bind_o;
	LIVECODE_READARG(ssh_bind_o, 0, "%p");
	ssh_session session;
	LIVECODE_READARG(session, 1, "%p");
	int result = ssh_bind_accept(ssh_bind_o, session);
	LIVECODE_ERR_OK(ssh_get_error(ssh_bind_o));
}
LIVECODE_FUNCTION(livessh_ssh_handle_key_exchange)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_handle_key_exchange(session);
	LIVECODE_ERR_OK(ssh_get_error(session));
}
LIVECODE_FUNCTION(livessh_ssh_bind_free)
{
	LIVECODE_ARG(1);
	ssh_bind ssh_bind_o;
	LIVECODE_READARG(ssh_bind_o, 0, "%p");
	ssh_bind_free(ssh_bind_o);
}
LIVECODE_FUNCTION(livessh_ssh_message_reply_default)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_reply_default(msg);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_message_auth_user)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_auth_user(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_auth_password)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_auth_password(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_auth_publickey)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	ssh_public_key result = ssh_message_auth_publickey(msg);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_message_auth_publickey_state)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	enum ssh_publickey_state_e result = ssh_message_auth_publickey_state(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_auth_reply_success)
{
	LIVECODE_ARG(2);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int partial;
	LIVECODE_READARG(partial, 1, "%d");
	int result = ssh_message_auth_reply_success(msg, partial);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_message_auth_reply_pk_ok)
{
	LIVECODE_ARG(3);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	ssh_string algo;
	LIVECODE_READARG(algo, 1, "%p");
	ssh_string pubkey;
	LIVECODE_READARG(pubkey, 2, "%p");
	int result = ssh_message_auth_reply_pk_ok(msg, algo, pubkey);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_auth_reply_pk_ok_simple)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_auth_reply_pk_ok_simple(msg);
	LIVECODE_RETURN_SIGNED;
}

LIVECODE_FUNCTION(livessh_ssh_message_auth_set_methods)
{
	LIVECODE_ARG(2);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int methods = 0;
	int i;
	for(i = 1; i < p_argument_count; ++i)
	{
		if(!strcmp(p_arguments[i], "unknown"))
		{
			methods = methods | SSH_AUTH_METHOD_UNKNOWN;
		}
		if(!strcmp(p_arguments[i], "password"))
		{
			methods = methods | SSH_AUTH_METHOD_PASSWORD;
		}
		if(!strcmp(p_arguments[i], "publickey"))
		{
			methods = methods | SSH_AUTH_METHOD_PUBLICKEY;
		}
		if(!strcmp(p_arguments[i], "hostbased"))
		{
			methods = methods | SSH_AUTH_METHOD_HOSTBASED;
		}
		if(!strcmp(p_arguments[i], "interactive"))
		{
			methods = methods | SSH_AUTH_METHOD_INTERACTIVE;
		}
	}
	int result = ssh_message_auth_set_methods(msg, methods);
	LIVECODE_ERR_OK("Error");
}
LIVECODE_FUNCTION(livessh_ssh_message_service_reply_success)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_service_reply_success(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_service_service)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_service_service(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_global_request_reply_success)
{
	LIVECODE_ARG(2);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	uint16_t bound_port;
	LIVECODE_READARG(bound_port, 1, "%p");
	int result = ssh_message_global_request_reply_success(msg, bound_port);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_execute_message_callbacks)
{
	LIVECODE_ARG(1);
	ssh_session session;
	LIVECODE_READARG(session, 0, "%p");
	int result = ssh_execute_message_callbacks(session);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_open_originator)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_channel_request_open_originator(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_open_originator_port)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_channel_request_open_originator_port(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_open_destination)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_channel_request_open_destination(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_open_destination_port)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_channel_request_open_destination_port(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_channel)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	ssh_channel result = ssh_message_channel_request_channel(msg);
	LIVECODE_RETURN_POINTER;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_pty_term)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_channel_request_pty_term(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_pty_width)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_channel_request_pty_width(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_pty_height)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_channel_request_pty_height(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_pty_pxwidth)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_channel_request_pty_pxwidth(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_pty_pxheight)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_channel_request_pty_pxheight(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_env_name)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_channel_request_env_name(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_env_value)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_channel_request_env_value(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_command)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_channel_request_command(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_channel_request_subsystem)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_channel_request_subsystem(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_global_request_address)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	char * result = ssh_message_global_request_address(msg);
	LIVECODE_RETURN_STRING;
}
LIVECODE_FUNCTION(livessh_ssh_message_global_request_port)
{
	LIVECODE_ARG(1);
	ssh_message msg;
	LIVECODE_READARG(msg, 0, "%p");
	int result = ssh_message_global_request_port(msg);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_open_reverse_forward)
{
	LIVECODE_ARG(5);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	const char * remotehost;
	remotehost = p_arguments[1];
	int remoteport;
	LIVECODE_READARG(remoteport, 2, "%d");
	const char * sourcehost;
	sourcehost = p_arguments[3];
	int localport;
	LIVECODE_READARG(localport, 4, "%d");
	int result = ssh_channel_open_reverse_forward(channel, remotehost, remoteport, sourcehost, localport);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_request_send_exit_status)
{
	LIVECODE_ARG(2);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	int exit_status;
	LIVECODE_READARG(exit_status, 1, "%d");
	int result = ssh_channel_request_send_exit_status(channel, exit_status);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_request_send_exit_signal)
{
	LIVECODE_ARG(5);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	const char * signum;
	signum = p_arguments[1];
	int core;
	LIVECODE_READARG(core, 2, "%d");
	const char * errmsg;
	errmsg = p_arguments[3];
	const char * lang;
	lang = p_arguments[4];
	int result = ssh_channel_request_send_exit_signal(channel, signum, core, errmsg, lang);
	LIVECODE_RETURN_SIGNED;
}
LIVECODE_FUNCTION(livessh_ssh_channel_write_stderr)
{
	LIVECODE_ARG(3);
	ssh_channel channel;
	LIVECODE_READARG(channel, 0, "%p");
	const void * data;
	LIVECODE_READARG(data, 1, "%p");
	uint32_t len;
	LIVECODE_READARG(len, 2, "%u");
	int result = ssh_channel_write_stderr(channel, data, len);
	LIVECODE_RETURN_SIGNED;
}

EXTERNAL_BEGIN_DECLARATIONS("ssh")
EXTERNAL_DECLARE_FUNCTION("ssh_channel_accept_x11", livessh_ssh_channel_accept_x11)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_change_pty_size", livessh_ssh_channel_change_pty_size)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_close", livessh_ssh_channel_close)
EXTERNAL_DECLARE_COMMAND("ssh_channel_free", livessh_ssh_channel_free)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_get_exit_status", livessh_ssh_channel_get_exit_status)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_get_session", livessh_ssh_channel_get_session)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_is_closed", livessh_ssh_channel_is_closed)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_is_eof", livessh_ssh_channel_is_eof)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_is_open", livessh_ssh_channel_is_open)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_new", livessh_ssh_channel_new)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_open_forward", livessh_ssh_channel_open_forward)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_open_session", livessh_ssh_channel_open_session)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_poll", livessh_ssh_channel_poll)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_read", livessh_ssh_channel_read)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_read_nonblocking", livessh_ssh_channel_read_nonblocking)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_env", livessh_ssh_channel_request_env)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_exec", livessh_ssh_channel_request_exec)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_pty", livessh_ssh_channel_request_pty)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_pty_size", livessh_ssh_channel_request_pty_size)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_shell", livessh_ssh_channel_request_shell)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_send_signal", livessh_ssh_channel_request_send_signal)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_subsystem", livessh_ssh_channel_request_subsystem)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_x11", livessh_ssh_channel_request_x11)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_send_eof", livessh_ssh_channel_send_eof)
EXTERNAL_DECLARE_COMMAND("ssh_channel_set_blocking", livessh_ssh_channel_set_blocking)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_write", livessh_ssh_channel_write)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_window_size", livessh_ssh_channel_window_size)
EXTERNAL_DECLARE_FUNCTION("ssh_try_publickey_from_file", livessh_ssh_try_publickey_from_file)
EXTERNAL_DECLARE_FUNCTION("ssh_basename", livessh_ssh_basename)
EXTERNAL_DECLARE_COMMAND("ssh_clean_pubkey_hash", livessh_ssh_clean_pubkey_hash)
EXTERNAL_DECLARE_COMMAND("ssh_connect", livessh_ssh_connect)
EXTERNAL_DECLARE_FUNCTION("ssh_copyright", livessh_ssh_copyright)
EXTERNAL_DECLARE_COMMAND("ssh_disconnect", livessh_ssh_disconnect)
EXTERNAL_DECLARE_FUNCTION("ssh_dirname", livessh_ssh_dirname)
EXTERNAL_DECLARE_FUNCTION("ssh_finalize", livessh_ssh_finalize)
EXTERNAL_DECLARE_FUNCTION("ssh_forward_accept", livessh_ssh_forward_accept)
EXTERNAL_DECLARE_FUNCTION("ssh_forward_cancel", livessh_ssh_forward_cancel)
EXTERNAL_DECLARE_FUNCTION("ssh_forward_listen", livessh_ssh_forward_listen)
EXTERNAL_DECLARE_COMMAND("ssh_free", livessh_ssh_free)
EXTERNAL_DECLARE_FUNCTION("ssh_get_disconnect_message", livessh_ssh_get_disconnect_message)
EXTERNAL_DECLARE_FUNCTION("ssh_get_error", livessh_ssh_get_error)
EXTERNAL_DECLARE_FUNCTION("ssh_get_error_code", livessh_ssh_get_error_code)
EXTERNAL_DECLARE_FUNCTION("ssh_get_fd", livessh_ssh_get_fd)
EXTERNAL_DECLARE_FUNCTION("ssh_get_hexa", livessh_ssh_get_hexa)
EXTERNAL_DECLARE_FUNCTION("ssh_get_issue_banner", livessh_ssh_get_issue_banner)
EXTERNAL_DECLARE_FUNCTION("ssh_get_openssh_version", livessh_ssh_get_openssh_version)
EXTERNAL_DECLARE_FUNCTION("ssh_get_pubkey", livessh_ssh_get_pubkey)
EXTERNAL_DECLARE_FUNCTION("ssh_get_pubkey_hash", livessh_ssh_get_pubkey_hash)
EXTERNAL_DECLARE_FUNCTION("ssh_get_random", livessh_ssh_get_random)
EXTERNAL_DECLARE_FUNCTION("ssh_get_version", livessh_ssh_get_version)
EXTERNAL_DECLARE_FUNCTION("ssh_get_status", livessh_ssh_get_status)
EXTERNAL_DECLARE_FUNCTION("ssh_init", livessh_ssh_init)
EXTERNAL_DECLARE_FUNCTION("ssh_is_blocking", livessh_ssh_is_blocking)
EXTERNAL_DECLARE_FUNCTION("ssh_is_connected", livessh_ssh_is_connected)
EXTERNAL_DECLARE_FUNCTION("ssh_is_server_known", livessh_ssh_is_server_known)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_open_reply_accept", livessh_ssh_message_channel_request_open_reply_accept)
EXTERNAL_DECLARE_COMMAND("ssh_message_channel_request_reply_success", livessh_ssh_message_channel_request_reply_success)
EXTERNAL_DECLARE_COMMAND("ssh_message_free", livessh_ssh_message_free)
EXTERNAL_DECLARE_FUNCTION("ssh_message_get", livessh_ssh_message_get)
EXTERNAL_DECLARE_FUNCTION("ssh_message_subtype", livessh_ssh_message_subtype)
EXTERNAL_DECLARE_FUNCTION("ssh_message_type", livessh_ssh_message_type)
EXTERNAL_DECLARE_FUNCTION("ssh_mkdir", livessh_ssh_mkdir)
EXTERNAL_DECLARE_FUNCTION("ssh_new", livessh_ssh_new)
EXTERNAL_DECLARE_FUNCTION("ssh_options_copy", livessh_ssh_options_copy)
EXTERNAL_DECLARE_FUNCTION("ssh_options_getopt", livessh_ssh_options_getopt)
EXTERNAL_DECLARE_FUNCTION("ssh_options_parse_config", livessh_ssh_options_parse_config)
EXTERNAL_DECLARE_COMMAND("ssh_options_set", livessh_ssh_options_set)
EXTERNAL_DECLARE_FUNCTION("ssh_pcap_file_close", livessh_ssh_pcap_file_close)
EXTERNAL_DECLARE_COMMAND("ssh_pcap_file_free", livessh_ssh_pcap_file_free)
EXTERNAL_DECLARE_FUNCTION("ssh_pcap_file_new", livessh_ssh_pcap_file_new)
EXTERNAL_DECLARE_FUNCTION("ssh_pcap_file_open", livessh_ssh_pcap_file_open)
// EXTERNAL_DECLARE_FUNCTION("ssh_privatekey_type", livessh_ssh_privatekey_type)
EXTERNAL_DECLARE_COMMAND("ssh_print_hexa", livessh_ssh_print_hexa)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_accept_request", livessh_ssh_scp_accept_request)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_close", livessh_ssh_scp_close)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_deny_request", livessh_ssh_scp_deny_request)
EXTERNAL_DECLARE_COMMAND("ssh_scp_free", livessh_ssh_scp_free)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_init", livessh_ssh_scp_init)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_leave_directory", livessh_ssh_scp_leave_directory)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_new", livessh_ssh_scp_new)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_pull_request", livessh_ssh_scp_pull_request)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_push_directory", livessh_ssh_scp_push_directory)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_push_file", livessh_ssh_scp_push_file)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_read", livessh_ssh_scp_read)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_request_get_filename", livessh_ssh_scp_request_get_filename)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_request_get_permissions", livessh_ssh_scp_request_get_permissions)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_request_get_size", livessh_ssh_scp_request_get_size)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_request_get_warning", livessh_ssh_scp_request_get_warning)
EXTERNAL_DECLARE_FUNCTION("ssh_scp_write", livessh_ssh_scp_write)
EXTERNAL_DECLARE_FUNCTION("ssh_service_request", livessh_ssh_service_request)
EXTERNAL_DECLARE_COMMAND("ssh_set_blocking", livessh_ssh_set_blocking)
EXTERNAL_DECLARE_COMMAND("ssh_set_fd_except", livessh_ssh_set_fd_except)
EXTERNAL_DECLARE_COMMAND("ssh_set_fd_toread", livessh_ssh_set_fd_toread)
EXTERNAL_DECLARE_COMMAND("ssh_set_fd_towrite", livessh_ssh_set_fd_towrite)
EXTERNAL_DECLARE_COMMAND("ssh_silent_disconnect", livessh_ssh_silent_disconnect)
EXTERNAL_DECLARE_FUNCTION("ssh_set_pcap_file", livessh_ssh_set_pcap_file)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_autopubkey", livessh_ssh_userauth_autopubkey)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_kbdint", livessh_ssh_userauth_kbdint)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_kbdint_getinstruction", livessh_ssh_userauth_kbdint_getinstruction)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_kbdint_getname", livessh_ssh_userauth_kbdint_getname)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_kbdint_getnprompts", livessh_ssh_userauth_kbdint_getnprompts)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_kbdint_getprompt", livessh_ssh_userauth_kbdint_getprompt)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_kbdint_setanswer", livessh_ssh_userauth_kbdint_setanswer)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_list", livessh_ssh_userauth_list)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_none", livessh_ssh_userauth_none)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_offer_pubkey", livessh_ssh_userauth_offer_pubkey)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_password", livessh_ssh_userauth_password)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_pubkey", livessh_ssh_userauth_pubkey)
EXTERNAL_DECLARE_FUNCTION("ssh_userauth_privatekey_file", livessh_ssh_userauth_privatekey_file)
EXTERNAL_DECLARE_FUNCTION("ssh_version", livessh_ssh_version)
EXTERNAL_DECLARE_FUNCTION("ssh_write_knownhost", livessh_ssh_write_knownhost)
EXTERNAL_DECLARE_COMMAND("ssh_string_burn", livessh_ssh_string_burn)
EXTERNAL_DECLARE_FUNCTION("ssh_string_copy", livessh_ssh_string_copy)
EXTERNAL_DECLARE_FUNCTION("ssh_string_data", livessh_ssh_string_data)
EXTERNAL_DECLARE_FUNCTION("ssh_string_fill", livessh_ssh_string_fill)
EXTERNAL_DECLARE_COMMAND("ssh_string_free", livessh_ssh_string_free)
EXTERNAL_DECLARE_FUNCTION("ssh_string_from_char", livessh_ssh_string_from_char)
EXTERNAL_DECLARE_FUNCTION("ssh_string_len", livessh_ssh_string_len)
EXTERNAL_DECLARE_FUNCTION("ssh_string_new", livessh_ssh_string_new)
EXTERNAL_DECLARE_FUNCTION("ssh_string_to_char", livessh_ssh_string_to_char)
EXTERNAL_DECLARE_COMMAND("ssh_string_free_char", livessh_ssh_string_free_char)
EXTERNAL_DECLARE_FUNCTION("ssh_getpass", livessh_ssh_getpass)
EXTERNAL_DECLARE_FUNCTION("sftp_new", livessh_sftp_new)
EXTERNAL_DECLARE_COMMAND("sftp_free", livessh_sftp_free)
EXTERNAL_DECLARE_FUNCTION("sftp_init", livessh_sftp_init)
EXTERNAL_DECLARE_FUNCTION("sftp_get_error", livessh_sftp_get_error)
EXTERNAL_DECLARE_FUNCTION("sftp_extensions_get_count", livessh_sftp_extensions_get_count)
EXTERNAL_DECLARE_FUNCTION("sftp_extensions_get_name", livessh_sftp_extensions_get_name)
EXTERNAL_DECLARE_FUNCTION("sftp_extensions_get_data", livessh_sftp_extensions_get_data)
EXTERNAL_DECLARE_FUNCTION("sftp_extension_supported", livessh_sftp_extension_supported)
EXTERNAL_DECLARE_FUNCTION("sftp_opendir", livessh_sftp_opendir)
EXTERNAL_DECLARE_FUNCTION("sftp_readdir", livessh_sftp_readdir)
EXTERNAL_DECLARE_FUNCTION("sftp_dir_eof", livessh_sftp_dir_eof)
EXTERNAL_DECLARE_FUNCTION("sftp_stat", livessh_sftp_stat)
EXTERNAL_DECLARE_FUNCTION("sftp_lstat", livessh_sftp_lstat)
EXTERNAL_DECLARE_FUNCTION("sftp_fstat", livessh_sftp_fstat)
EXTERNAL_DECLARE_COMMAND("sftp_attributes_free", livessh_sftp_attributes_free)
EXTERNAL_DECLARE_FUNCTION("sftp_closedir", livessh_sftp_closedir)
EXTERNAL_DECLARE_COMMAND("sftp_close", livessh_sftp_close)
EXTERNAL_DECLARE_FUNCTION("sftp_open", livessh_sftp_open)
EXTERNAL_DECLARE_COMMAND("sftp_file_set_nonblocking", livessh_sftp_file_set_nonblocking)
EXTERNAL_DECLARE_COMMAND("sftp_file_set_blocking", livessh_sftp_file_set_blocking)
EXTERNAL_DECLARE_FUNCTION("sftp_read", livessh_sftp_read)
EXTERNAL_DECLARE_FUNCTION("sftp_async_read_begin", livessh_sftp_async_read_begin)
EXTERNAL_DECLARE_FUNCTION("sftp_async_read", livessh_sftp_async_read)
EXTERNAL_DECLARE_FUNCTION("sftp_write", livessh_sftp_write)
EXTERNAL_DECLARE_FUNCTION("sftp_seek", livessh_sftp_seek)
EXTERNAL_DECLARE_FUNCTION("sftp_seek64", livessh_sftp_seek64)
EXTERNAL_DECLARE_FUNCTION("sftp_tell", livessh_sftp_tell)
EXTERNAL_DECLARE_FUNCTION("sftp_tell64", livessh_sftp_tell64)
EXTERNAL_DECLARE_COMMAND("sftp_rewind", livessh_sftp_rewind)
EXTERNAL_DECLARE_FUNCTION("sftp_unlink", livessh_sftp_unlink)
EXTERNAL_DECLARE_FUNCTION("sftp_rmdir", livessh_sftp_rmdir)
EXTERNAL_DECLARE_FUNCTION("sftp_mkdir", livessh_sftp_mkdir)
EXTERNAL_DECLARE_FUNCTION("sftp_rename", livessh_sftp_rename)
EXTERNAL_DECLARE_FUNCTION("sftp_setstat", livessh_sftp_setstat)
EXTERNAL_DECLARE_FUNCTION("sftp_chown", livessh_sftp_chown)
EXTERNAL_DECLARE_FUNCTION("sftp_chmod", livessh_sftp_chmod)
EXTERNAL_DECLARE_FUNCTION("sftp_utimes", livessh_sftp_utimes)
EXTERNAL_DECLARE_FUNCTION("sftp_symlink", livessh_sftp_symlink)
EXTERNAL_DECLARE_FUNCTION("sftp_readlink", livessh_sftp_readlink)
EXTERNAL_DECLARE_FUNCTION("sftp_statvfs", livessh_sftp_statvfs)
EXTERNAL_DECLARE_FUNCTION("sftp_fstatvfs", livessh_sftp_fstatvfs)
EXTERNAL_DECLARE_COMMAND("sftp_statvfs_free", livessh_sftp_statvfs_free)
EXTERNAL_DECLARE_FUNCTION("sftp_canonicalize_path", livessh_sftp_canonicalize_path)
EXTERNAL_DECLARE_FUNCTION("sftp_server_version", livessh_sftp_server_version)
EXTERNAL_DECLARE_FUNCTION("sftp_server_new", livessh_sftp_server_new)
EXTERNAL_DECLARE_FUNCTION("sftp_server_init", livessh_sftp_server_init)

EXTERNAL_DECLARE_COMMAND("livessh_run_command", livessh_run_command)
// server

EXTERNAL_DECLARE_FUNCTION("ssh_bind_new", livessh_ssh_bind_new)
EXTERNAL_DECLARE_COMMAND("ssh_bind_options_set", livessh_ssh_bind_options_set)
EXTERNAL_DECLARE_COMMAND("ssh_bind_listen", livessh_ssh_bind_listen)
EXTERNAL_DECLARE_FUNCTION("ssh_bind_set_callbacks", livessh_ssh_bind_set_callbacks)
EXTERNAL_DECLARE_COMMAND("ssh_bind_set_blocking", livessh_ssh_bind_set_blocking)
EXTERNAL_DECLARE_FUNCTION("ssh_bind_get_fd", livessh_ssh_bind_get_fd)
EXTERNAL_DECLARE_COMMAND("ssh_bind_set_fd", livessh_ssh_bind_set_fd)
EXTERNAL_DECLARE_COMMAND("ssh_bind_fd_toaccept", livessh_ssh_bind_fd_toaccept)
EXTERNAL_DECLARE_COMMAND("ssh_bind_accept", livessh_ssh_bind_accept)
EXTERNAL_DECLARE_COMMAND("ssh_handle_key_exchange", livessh_ssh_handle_key_exchange)
EXTERNAL_DECLARE_COMMAND("ssh_bind_free", livessh_ssh_bind_free)
EXTERNAL_DECLARE_COMMAND("ssh_message_reply_default", livessh_ssh_message_reply_default)
EXTERNAL_DECLARE_FUNCTION("ssh_message_auth_user", livessh_ssh_message_auth_user)
EXTERNAL_DECLARE_FUNCTION("ssh_message_auth_password", livessh_ssh_message_auth_password)
EXTERNAL_DECLARE_FUNCTION("ssh_message_auth_publickey", livessh_ssh_message_auth_publickey)
EXTERNAL_DECLARE_FUNCTION("ssh_message_auth_publickey_state", livessh_ssh_message_auth_publickey_state)
EXTERNAL_DECLARE_COMMAND("ssh_message_auth_reply_success", livessh_ssh_message_auth_reply_success)
EXTERNAL_DECLARE_FUNCTION("ssh_message_auth_reply_pk_ok", livessh_ssh_message_auth_reply_pk_ok)
EXTERNAL_DECLARE_FUNCTION("ssh_message_auth_reply_pk_ok_simple", livessh_ssh_message_auth_reply_pk_ok_simple)
EXTERNAL_DECLARE_FUNCTION("ssh_message_auth_set_methods", livessh_ssh_message_auth_set_methods)
EXTERNAL_DECLARE_COMMAND("ssh_message_service_reply_success", livessh_ssh_message_service_reply_success)
EXTERNAL_DECLARE_FUNCTION("ssh_message_service_service", livessh_ssh_message_service_service)
EXTERNAL_DECLARE_COMMAND("ssh_message_global_request_reply_success", livessh_ssh_message_global_request_reply_success)
EXTERNAL_DECLARE_FUNCTION("ssh_execute_message_callbacks", livessh_ssh_execute_message_callbacks)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_open_originator", livessh_ssh_message_channel_request_open_originator)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_open_originator_port", livessh_ssh_message_channel_request_open_originator_port)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_open_destination", livessh_ssh_message_channel_request_open_destination)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_open_destination_port", livessh_ssh_message_channel_request_open_destination_port)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_channel", livessh_ssh_message_channel_request_channel)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_pty_term", livessh_ssh_message_channel_request_pty_term)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_pty_width", livessh_ssh_message_channel_request_pty_width)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_pty_height", livessh_ssh_message_channel_request_pty_height)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_pty_pxwidth", livessh_ssh_message_channel_request_pty_pxwidth)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_pty_pxheight", livessh_ssh_message_channel_request_pty_pxheight)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_env_name", livessh_ssh_message_channel_request_env_name)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_env_value", livessh_ssh_message_channel_request_env_value)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_command", livessh_ssh_message_channel_request_command)
EXTERNAL_DECLARE_FUNCTION("ssh_message_channel_request_subsystem", livessh_ssh_message_channel_request_subsystem)
EXTERNAL_DECLARE_FUNCTION("ssh_message_global_request_address", livessh_ssh_message_global_request_address)
EXTERNAL_DECLARE_FUNCTION("ssh_message_global_request_port", livessh_ssh_message_global_request_port)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_open_reverse_forward", livessh_ssh_channel_open_reverse_forward)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_send_exit_status", livessh_ssh_channel_request_send_exit_status)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_request_send_exit_signal", livessh_ssh_channel_request_send_exit_signal)
EXTERNAL_DECLARE_FUNCTION("ssh_channel_write_stderr", livessh_ssh_channel_write_stderr)

EXTERNAL_END_DECLARATIONS
